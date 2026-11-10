"""Ingesta en vivo de la GUI: sesiones de Hermes + tráfico de Caido -> ``TraceStore``.

Tres piezas, todas OBSERVADORAS (solo leen; nunca lanzan, dirigen ni paran al agente):

  - ``Notifier``: despertador asyncio. El ingestor lo toca al insertar eventos y cada
    stream SSE abierto en el navegador despierta y lee ``seq > cursor`` del store.
  - ``SessionIngestor``: sondea ``GET /api/sessions`` (con subagentes) y, para cada sesión que
    cambió, pide sus mensajes NUEVOS (``GET /api/sessions/{id}/messages``) y los ingiere. Al
    ver el resultado de un ``record_finding`` CONFIRMADO, graba el PoC a disco (``.cast`` +
    ``.md``) en ``poc_dir`` — la "grabación" del PoC sobrevive al contenedor (volumen).
  - ``CaidoFeed``: sondea el historial de Caido (el mismo ``caido_client`` que usa
    ``kali-mcp``, sesión de invitado) y lo ingiere como eventos ``web.request``: qué está
    tocando el agente en la web, en vivo.

Version-tolerante: el contrato de ``:8642`` es de Hermes; se leen campos con ``.get`` y un
fallo de red/forma se refleja en ``status`` (``last_error``) sin tumbar el bucle. "No se
finge": si Hermes o Caido no responden, el estado lo dice; no se inventan datos.
"""

from __future__ import annotations

import asyncio
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Callable, Optional

import httpx

import event_model as em
import poc_replay
from trace_store import TraceStore

# Página de mensajes por petición (máximo que acepta Hermes).
PAGE = 500
# Mensajes recientes que se piden en una sincronización incremental.
INCREMENTAL = 200
# Sesiones con actividad en los últimos N s se re-sincronizan en cada vuelta aunque sus
# contadores no cambien (red de seguridad barata frente a un contador perezoso).
ACTIVE_WINDOW_S = 90.0
# Gracia para ingerir una petición de Caido aún sin respuesta (después queda "pendiente").
CAIDO_PENDING_GRACE_S = 20.0

_SAFE_NAME = re.compile(r"[^A-Za-z0-9_.-]+")


def _log(msg: str) -> None:
    sys.stderr.write("[vulnerator-web] %s\n" % msg)
    sys.stderr.flush()


class Notifier:
    """Despertador para los streams: ``notify()`` despierta a todos los ``wait()`` pendientes."""

    def __init__(self) -> None:
        self._version = 0
        self._cond: Optional[asyncio.Condition] = None

    def _c(self) -> asyncio.Condition:
        if self._cond is None:
            self._cond = asyncio.Condition()
        return self._cond

    @property
    def version(self) -> int:
        return self._version

    async def notify_async(self) -> None:
        cond = self._c()
        async with cond:
            self._version += 1
            cond.notify_all()

    def notify(self) -> None:
        """Versión síncrona segura desde el event loop (programa la notificación)."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            self._version += 1
            return
        loop.create_task(self.notify_async())

    async def wait(self, seen_version: int, timeout: float) -> int:
        """Espera hasta que ``version`` supere ``seen_version`` o venza ``timeout``."""
        cond = self._c()
        async with cond:
            if self._version > seen_version:
                return self._version
            try:
                await asyncio.wait_for(
                    cond.wait_for(lambda: self._version > seen_version), timeout
                )
            except asyncio.TimeoutError:
                pass
            return self._version


def session_fingerprint(meta: dict[str, Any]) -> tuple:
    return tuple(meta.get(k) for k in (
        "message_count", "tool_call_count", "last_active", "ended_at"))


def select_ready_entries(entries: list[dict[str, Any]], now: float,
                         grace: float = CAIDO_PENDING_GRACE_S) -> list[dict[str, Any]]:
    """Entradas de Caido listas para ingerir: con respuesta, o sin ella pasada la gracia.

    La dedup del store es por id; si se ingiriera una petición antes de llegar su respuesta,
    su código de estado no se actualizaría nunca. Por eso se espera un poco a la respuesta.
    """
    ready = []
    for e in entries:
        if not isinstance(e, dict) or e.get("id") in (None, ""):
            continue
        if isinstance(e.get("response"), dict) and e["response"].get("statusCode") is not None:
            ready.append(e)
            continue
        from trace_store import _caido_ts  # local: helper puro del store
        created = _caido_ts(e.get("createdAt"))
        if created and now - created >= grace:
            ready.append(e)
    ready.sort(key=lambda e: str(e.get("id")).zfill(20))
    return ready


class HermesSessions:
    """Cliente mínimo (lectura) de la API de sesiones de Hermes en ``:8642``."""

    def __init__(self, base_url: str, api_key: str, timeout: float = 20.0) -> None:
        self._base = base_url.rstrip("/")
        self._client = httpx.AsyncClient(
            base_url=self._base,
            headers={"Authorization": "Bearer %s" % api_key},
            timeout=httpx.Timeout(timeout, connect=5.0),
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def _get(self, path: str, params: Optional[dict[str, Any]] = None) -> Any:
        resp = await self._client.get(path, params=params)
        if resp.status_code >= 400:
            snippet = (resp.text or "")[:200]
            raise RuntimeError("Hermes %s -> HTTP %s: %s" % (path, resp.status_code, snippet))
        return resp.json()

    async def health(self) -> dict[str, Any]:
        doc = await self._get("/health")
        return doc if isinstance(doc, dict) else {}

    async def list_sessions(self, limit: int = 50) -> list[dict[str, Any]]:
        doc = await self._get("/api/sessions", {"limit": limit, "include_children": "true"})
        rows = doc.get("data") if isinstance(doc, dict) else doc
        return [r for r in (rows or []) if isinstance(r, dict) and r.get("id")]

    async def messages(self, session_id: str, *, order: str, offset: int = 0,
                       limit: int = PAGE) -> list[dict[str, Any]]:
        from urllib.parse import quote
        path = "/api/sessions/%s/messages" % quote(session_id, safe="")
        doc = await self._get(path, {"order": order, "offset": offset, "limit": limit})
        rows = doc.get("data") if isinstance(doc, dict) else doc
        return [r for r in (rows or []) if isinstance(r, dict)]


class SessionIngestor:
    """Bucle de sondeo de sesiones -> store (+ grabación de PoCs confirmados)."""

    def __init__(self, store: TraceStore, notifier: Notifier, hermes: HermesSessions, *,
                 interval: float = 1.5, session_limit: int = 50,
                 poc_dir: Optional[str] = None) -> None:
        self.store = store
        self.notifier = notifier
        self.hermes = hermes
        self.interval = interval
        self.session_limit = session_limit
        self.poc_dir = Path(poc_dir) if poc_dir else None
        self._fp: dict[str, tuple] = {}
        self._saved_pocs: set[str] = set()
        self.status: dict[str, Any] = {
            "ok": False, "last_poll": None, "last_error": None, "hermes_version": None,
            "sessions": 0, "pocs_recorded": 0,
        }

    async def run(self) -> None:
        version_checked = 0.0
        while True:
            try:
                if time.time() - version_checked > 60:
                    health = await self.hermes.health()
                    self.status["hermes_version"] = health.get("version")
                    version_checked = time.time()
                await self.poll_once()
                self.status.update(ok=True, last_error=None)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # red/forma: se refleja en status, el bucle sigue
                self.status.update(ok=False, last_error=em.one_line(str(exc), 300))
            self.status["last_poll"] = time.time()
            await asyncio.sleep(self.interval)

    async def poll_once(self) -> int:
        """Una vuelta: lista sesiones y sincroniza las que cambiaron. Devuelve eventos nuevos."""
        sessions = await self.hermes.list_sessions(self.session_limit)
        self.status["sessions"] = len(sessions)
        now = time.time()
        total = 0
        touched = False
        for meta in sessions:
            sid = meta["id"]
            if self.store.upsert_session(meta):
                touched = True
            fp = session_fingerprint(meta)
            try:
                active = now - float(meta.get("last_active") or 0) < ACTIVE_WINDOW_S
            except (TypeError, ValueError):
                active = False
            if self._fp.get(sid) != fp or active:
                total += await self.sync_session(sid)
                self._fp[sid] = fp
        if total or touched:
            self.notifier.notify()
        return total

    async def sync_session(self, sid: str) -> int:
        seen = self.store.seen_message_ids(sid)
        msgs: list[dict[str, Any]]
        if seen:
            msgs = await self.hermes.messages(sid, order="latest", limit=INCREMENTAL)
            fresh = [m for m in msgs if _mid(m) is not None and _mid(m) not in seen]
            if len(msgs) >= INCREMENTAL and len(fresh) == len(msgs):
                msgs = await self._full(sid)  # posible hueco: re-sincroniza entero
        else:
            msgs = await self._full(sid)
        new = self.store.ingest_messages(sid, msgs)
        if new:
            self._maybe_record_pocs(sid, new)
        return len(new)

    async def _full(self, sid: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        offset = 0
        for _ in range(200):  # tope de seguridad: 100k mensajes
            page = await self.hermes.messages(sid, order="oldest", offset=offset, limit=PAGE)
            out.extend(page)
            if len(page) < PAGE:
                break
            offset += len(page)
        return out

    def _maybe_record_pocs(self, sid: str, new_events: list[dict[str, Any]]) -> None:
        """Si llegó el resultado de un ``record_finding``, graba los PoCs confirmados a disco."""
        if self.poc_dir is None:
            return
        if not any(ev.get("kind") == em.KIND_TOOL_RESULT
                   and str(ev.get("tool") or "").endswith("record_finding") for ev in new_events):
            return
        try:
            pocs = poc_replay.build_pocs(self.store.session_events(sid))
        except Exception as exc:
            _log("no se pudo construir el PoC de %s: %s" % (sid, exc))
            return
        for poc in pocs:
            if not poc["confirmed"] or poc["store_status"] != "recorded":
                continue
            if poc["id"] in self._saved_pocs:
                continue
            try:
                write_poc_files(self.poc_dir, poc)
                self._saved_pocs.add(poc["id"])
                self.status["pocs_recorded"] = len(self._saved_pocs)
                _log("PoC grabado: %s" % em.one_line(poc["finding"]["title"], 120))
            except OSError as exc:
                _log("no se pudo grabar el PoC: %s" % exc)


def safe_component(value: Any, fallback: str, limit: int) -> str:
    """Un componente de ruta seguro: solo ``[A-Za-z0-9_.-]``, sin puntos/guiones iniciales.

    Quitar los puntos del borde impide ``.``/``..`` (recorrido) y ficheros ocultos aunque el
    valor (título del hallazgo, id de sesión: DATO NO CONFIABLE) venga manipulado.
    """
    out = _SAFE_NAME.sub("-", str(value or "")).strip("-.")[:limit].strip("-.")
    return out or fallback


def poc_basename(poc: dict[str, Any]) -> str:
    """Nombre de fichero seguro para un PoC (sin separadores ni recorridos)."""
    title = safe_component(poc["finding"]["title"], "poc", 60)
    call = safe_component(poc.get("call_id"), "call", 40)
    return "%s__%s" % (title, call)


def write_poc_files(poc_dir: Path, poc: dict[str, Any]) -> Path:
    """Escribe ``<poc_dir>/<sesión>/<poc>.cast`` y ``.md`` (atómico por fichero)."""
    folder = poc_dir / safe_component(poc.get("session_id"), "session", 80)
    folder.mkdir(parents=True, exist_ok=True)
    base = folder / poc_basename(poc)
    for suffix, body in ((".cast", poc_replay.to_asciicast(poc)), (".md", poc_replay.to_markdown(poc))):
        tmp = base.with_suffix(suffix + ".tmp")
        tmp.write_text(body, encoding="utf-8")
        os.replace(tmp, base.with_suffix(suffix))
    return base


def _mid(m: dict[str, Any]) -> Optional[int]:
    try:
        return int(m.get("id"))
    except (TypeError, ValueError):
        return None


class CaidoFeed:
    """Sondeo del historial de Caido -> eventos ``web.request``."""

    def __init__(self, store: TraceStore, notifier: Notifier,
                 search: Callable[..., dict[str, Any]], *, interval: float = 3.0,
                 limit: int = 100) -> None:
        self.store = store
        self.notifier = notifier
        self.search = search
        self.interval = interval
        self.limit = limit
        self.status: dict[str, Any] = {"enabled": True, "ok": False, "last_poll": None,
                                       "last_error": None, "requests": 0}

    async def run(self) -> None:
        while True:
            try:
                await self.poll_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.status.update(ok=False, last_error=em.one_line(str(exc), 300))
            self.status["last_poll"] = time.time()
            await asyncio.sleep(self.interval)

    async def poll_once(self) -> int:
        result = await asyncio.to_thread(self.search, "", self.limit)
        if not isinstance(result, dict) or result.get("status") != "done":
            reason = (result or {}).get("status") if isinstance(result, dict) else "sin respuesta"
            detail = (result or {}).get("error") if isinstance(result, dict) else None
            self.status.update(ok=False, last_error=em.one_line(
                "%s%s" % (reason, (": %s" % detail) if detail else ""), 300))
            return 0
        self.status.update(ok=True, last_error=None, requests=result.get("count"))
        ready = select_ready_entries(result.get("entries") or [], time.time())
        new = self.store.ingest_web(ready)
        if new:
            self.notifier.notify()
        return len(new)
