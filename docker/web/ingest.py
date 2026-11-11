"""Live ingestion for the GUI: Hermes sessions + Caido traffic -> ``TraceStore``.

Three pieces, all OBSERVERS (read only; they never launch, steer, or stop the agent):

  - ``Notifier``: asyncio wake-up. The ingestor pokes it when inserting events and each
    SSE stream open in the browser wakes up and reads ``seq > cursor`` from the store.
  - ``SessionIngestor``: polls ``GET /api/sessions`` (with subagents) and, for each session that
    changed, requests its NEW messages (``GET /api/sessions/{id}/messages``) and ingests them. When
    it sees the result of a CONFIRMED ``record_finding``, it records the PoC to disk (``.cast`` +
    ``.md``) in ``poc_dir`` — the PoC "recording" survives the container (volume).
  - ``CaidoFeed``: polls Caido's history (the same ``caido_client`` that
    ``kali-mcp`` uses, guest session) and ingests it as ``web.request`` events: what the
    agent is touching on the web, live.

Version-tolerant: the ``:8642`` contract belongs to Hermes; fields are read with ``.get`` and a
network/shape failure is reflected in ``status`` (``last_error``) without killing the loop. "No
pretending": if Hermes or Caido do not respond, the state says so; no data is made up.
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

# Page of messages per request (the maximum Hermes accepts).
PAGE = 500
# Recent messages requested in an incremental sync.
INCREMENTAL = 200
# Sessions with activity in the last N s are re-synced on every pass even if their
# counters do not change (a cheap safety net against a lazy counter).
ACTIVE_WINDOW_S = 90.0
# Grace period to ingest a Caido request that still has no response (afterwards it stays "pending").
CAIDO_PENDING_GRACE_S = 20.0

_SAFE_NAME = re.compile(r"[^A-Za-z0-9_.-]+")


def _log(msg: str) -> None:
    sys.stderr.write("[vulnerator-web] %s\n" % msg)
    sys.stderr.flush()


class Notifier:
    """Wake-up for the streams: ``notify()`` wakes all pending ``wait()`` calls."""

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
        """Synchronous version safe to call from the event loop (schedules the notification)."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            self._version += 1
            return
        loop.create_task(self.notify_async())

    async def wait(self, seen_version: int, timeout: float) -> int:
        """Waits until ``version`` exceeds ``seen_version`` or ``timeout`` elapses."""
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
    """Caido entries ready to ingest: with a response, or without one past the grace period.

    The store's dedup is by id; if a request were ingested before its response arrived,
    its status code would never be updated. That is why we wait a bit for the response.
    """
    ready = []
    for e in entries:
        if not isinstance(e, dict) or e.get("id") in (None, ""):
            continue
        if isinstance(e.get("response"), dict) and e["response"].get("statusCode") is not None:
            ready.append(e)
            continue
        from trace_store import _caido_ts  # local: pure helper from the store
        created = _caido_ts(e.get("createdAt"))
        if created and now - created >= grace:
            ready.append(e)
    ready.sort(key=lambda e: str(e.get("id")).zfill(20))
    return ready


class HermesSessions:
    """Minimal (read-only) client for Hermes' sessions API at ``:8642``."""

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
    """Session polling loop -> store (+ recording of confirmed PoCs)."""

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
            except Exception as exc:  # network/shape: reflected in status, the loop continues
                self.status.update(ok=False, last_error=em.one_line(str(exc), 300))
            self.status["last_poll"] = time.time()
            await asyncio.sleep(self.interval)

    async def poll_once(self) -> int:
        """One pass: lists sessions and syncs the ones that changed. Returns the number of new events."""
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
                msgs = await self._full(sid)  # possible gap: re-sync the whole thing
        else:
            msgs = await self._full(sid)
        new = self.store.ingest_messages(sid, msgs)
        if new:
            self._maybe_record_pocs(sid, new)
        return len(new)

    async def _full(self, sid: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        offset = 0
        for _ in range(200):  # safety cap: 100k messages
            page = await self.hermes.messages(sid, order="oldest", offset=offset, limit=PAGE)
            out.extend(page)
            if len(page) < PAGE:
                break
            offset += len(page)
        return out

    def _maybe_record_pocs(self, sid: str, new_events: list[dict[str, Any]]) -> None:
        """If a ``record_finding`` result arrived, records the confirmed PoCs to disk."""
        if self.poc_dir is None:
            return
        if not any(ev.get("kind") == em.KIND_TOOL_RESULT
                   and str(ev.get("tool") or "").endswith("record_finding") for ev in new_events):
            return
        try:
            pocs = poc_replay.build_pocs(self.store.session_events(sid))
        except Exception as exc:
            _log("could not build the PoC for %s: %s" % (sid, exc))
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
                _log("PoC recorded: %s" % em.one_line(poc["finding"]["title"], 120))
            except OSError as exc:
                _log("could not record the PoC: %s" % exc)


def safe_component(value: Any, fallback: str, limit: int) -> str:
    """A safe path component: only ``[A-Za-z0-9_.-]``, no leading dots/dashes.

    Stripping the edge dots prevents ``.``/``..`` (traversal) and hidden files even if the
    value (finding title, session id: UNTRUSTED DATA) comes in tampered with.
    """
    out = _SAFE_NAME.sub("-", str(value or "")).strip("-.")[:limit].strip("-.")
    return out or fallback


def poc_basename(poc: dict[str, Any]) -> str:
    """Safe file name for a PoC (no separators or traversals)."""
    title = safe_component(poc["finding"]["title"], "poc", 60)
    call = safe_component(poc.get("call_id"), "call", 40)
    return "%s__%s" % (title, call)


def write_poc_files(poc_dir: Path, poc: dict[str, Any]) -> Path:
    """Writes ``<poc_dir>/<session>/<poc>.cast`` and ``.md`` (atomic per file)."""
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
    """Polling of Caido's history -> ``web.request`` events."""

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
            reason = (result or {}).get("status") if isinstance(result, dict) else "no response"
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
