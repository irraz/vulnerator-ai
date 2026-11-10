"""Normalización de mensajes de sesión de Hermes a EVENTOS de la GUI (STDLIB PURA).

Fuente: ``GET /api/sessions/{id}/messages`` de la API de Hermes (``:8642``). Hermes persiste
la llamada a una tool ANTES de ejecutarla y su resultado al terminar (ver
``agent/turn_tool_round.py`` / ``agent/tool_executor.py`` en hermes-agent), así que sondear
los mensajes da casi en vivo TODO lo que hace el agente, venga la sesión de la API, de la
TUI, de la Webapp o de un subagente delegado.

Cada mensaje se convierte en 0..N eventos con un esquema estable e interno de la GUI:

    {key, session_id, message_id, ts, kind, role?, phase?, step?, tool?, tool_display?,
     category?, call_id?, args?, summary?, text?, truncated?}

``kind`` ∈ ``KINDS``. ``key`` es único y estable (dedup idempotente al re-sincronizar).

Disciplina de seguridad: TODO el contenido (texto del asistente, razonamiento, args y salida
de tools) es DATO NO CONFIABLE (puede traer prompt-injection o HTML). Aquí solo se
transporta, se acota en tamaño y se etiqueta; NUNCA se interpreta ni se ejecuta. El frontend
lo pinta siempre como texto (``textContent``), nunca como HTML.
"""

from __future__ import annotations

import json
from typing import Any, Iterable

import ooda_parse

KIND_USER = "user"
KIND_OODA = "ooda"
KIND_ASSISTANT = "assistant"
KIND_REASONING = "reasoning"
KIND_TOOL_CALL = "tool.call"
KIND_TOOL_RESULT = "tool.result"
KIND_WEB = "web.request"

KINDS = (
    KIND_USER, KIND_OODA, KIND_ASSISTANT, KIND_REASONING,
    KIND_TOOL_CALL, KIND_TOOL_RESULT, KIND_WEB,
)

# Tope de bytes de texto por evento que se PERSISTE (la salida completa de un escaneo puede
# ser enorme; el crudo íntegro vive en el plano de artefactos de Kali :8901).
TEXT_MAX = 64 * 1024
# Tope del resumen de una línea que se enseña en listas/terminal.
SUMMARY_MAX = 240

# Prefijos con los que Hermes nombra las tools de cada servidor MCP del perfil.
_MCP_PREFIXES = ("mcp_kali_", "mcp_playwright_", "mcp_vulnerator_", "mcp_")

# Campos de args que mejor resumen una llamada, por orden de preferencia.
_SUMMARY_KEYS = (
    "command", "url", "httpql", "query", "element", "text", "goal", "title",
    "domain", "target", "path", "code", "prompt", "input",
)


def clip(text: Any, limit: int = TEXT_MAX) -> tuple[str, bool]:
    """Coacciona a str y acota a ``limit`` caracteres. Devuelve ``(texto, truncado)``."""
    if text is None:
        return "", False
    if not isinstance(text, str):
        try:
            text = json.dumps(text, ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            text = str(text)
    if len(text) <= limit:
        return text, False
    return text[:limit], True


def one_line(text: Any, limit: int = SUMMARY_MAX) -> str:
    """Resumen de una sola línea (sin saltos), acotado."""
    s, _ = clip(text, limit * 4)
    s = " ".join(s.split())
    return s if len(s) <= limit else s[: limit - 1] + "…"


def tool_display_name(name: str | None) -> str:
    """Nombre corto de la tool sin el prefijo del servidor MCP (``mcp_kali_kali_run`` -> ``kali_run``)."""
    n = name or ""
    for prefix in _MCP_PREFIXES:
        if n.startswith(prefix) and len(n) > len(prefix):
            return n[len(prefix):]
    return n


def tool_category(name: str | None) -> str:
    """Familia de la tool para colorear/filtrar: shell, browser, web, finding, recon, ..."""
    n = (name or "").lower()
    if "record_finding" in n or "read_findings" in n:
        return "finding"
    if "playwright" in n or "browser_" in n or n == "browser":
        return "browser"
    if "caido" in n:
        return "web"
    if any(k in n for k in ("kali_run", "kali_exec", "shell", "terminal", "execute_code")):
        return "shell"
    if "kanban" in n or "todo" in n:
        return "tracking"
    if "delegate" in n or "subagent" in n:
        return "subagent"
    if any(k in n for k in (
        "dns_recon", "webtech_scan", "prowler", "iam_", "start_collection", "scan_",
        "read_tool_logs", "get_scan_status",
    )):
        return "recon"
    return "tool"


def content_text(content: Any) -> str:
    """Texto plano de un ``content`` de mensaje (str o lista de partes multimodales)."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for part in content:
            if isinstance(part, dict):
                if isinstance(part.get("text"), str):
                    parts.append(part["text"])
                elif part.get("type") in ("image_url", "image", "input_image"):
                    parts.append("[imagen]")
            elif isinstance(part, str):
                parts.append(part)
        return "\n".join(parts)
    return clip(content)[0]


def parse_args(raw: Any) -> Any:
    """Args de una tool-call: JSON-string -> objeto; si no parsea, se devuelve el string."""
    if isinstance(raw, (dict, list)):
        return raw
    if isinstance(raw, str):
        s = raw.strip()
        if not s:
            return {}
        try:
            return json.loads(s)
        except (ValueError, TypeError):
            return raw
    return {} if raw is None else raw


def parse_tool_calls(raw: Any) -> list[dict[str, Any]]:
    """Lista normalizada ``[{id, name, args}]`` a partir de ``tool_calls`` (str JSON o lista).

    Tolera las variantes OpenAI (``{id, function:{name, arguments}}``) y planas
    (``{id|call_id, name, arguments|args|input}``).
    """
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (ValueError, TypeError):
            return []
    if isinstance(raw, dict):
        raw = [raw]
    if not isinstance(raw, list):
        return []
    out = []
    for i, tc in enumerate(raw):
        if not isinstance(tc, dict):
            continue
        fn = tc.get("function") if isinstance(tc.get("function"), dict) else {}
        name = fn.get("name") or tc.get("name") or ""
        args_raw = fn.get("arguments", tc.get("arguments", tc.get("args", tc.get("input"))))
        call_id = tc.get("id") or tc.get("call_id") or tc.get("tool_call_id") or ""
        out.append({
            "id": str(call_id) if call_id else "",
            "index": i,
            "name": str(name),
            "args": parse_args(args_raw),
        })
    return out


def summarize_args(args: Any) -> str:
    """Resumen de una línea de los args de una tool (el comando, la URL, la query...)."""
    if isinstance(args, dict):
        for key in _SUMMARY_KEYS:
            val = args.get(key)
            if isinstance(val, str) and val.strip():
                return one_line(val)
            if isinstance(val, list) and val and all(isinstance(v, str) for v in val):
                return one_line(" ".join(val))
        if not args:
            return ""
        return one_line(json.dumps(args, ensure_ascii=False, default=str))
    return one_line(args)


def _ts(message: dict[str, Any]) -> float:
    ts = message.get("timestamp")
    try:
        return float(ts)
    except (TypeError, ValueError):
        return 0.0


def message_to_events(session_id: str, message: dict[str, Any]) -> list[dict[str, Any]]:
    """Convierte UN mensaje de sesión de Hermes en 0..N eventos de la GUI (orden estable)."""
    if not isinstance(message, dict):
        return []
    mid = message.get("id")
    if mid is None:
        return []
    role = message.get("role") or ""
    ts = _ts(message)
    base = {"session_id": session_id, "message_id": mid, "ts": ts, "role": role}
    events: list[dict[str, Any]] = []

    def emit(suffix: str, kind: str, **fields: Any) -> None:
        ev = dict(base)
        ev["key"] = "%s:m%s:%s" % (session_id, mid, suffix)
        ev["kind"] = kind
        ev.update(fields)
        events.append(ev)

    if role == "user":
        text, trunc = clip(content_text(message.get("content")))
        if text.strip():
            emit("user", KIND_USER, text=text, truncated=trunc, summary=one_line(text))

    elif role == "assistant":
        # La línea OODA va PRIMERO: es la cabecera del paso. El razonamiento del mismo mensaje
        # pertenece a ese paso (se pinta debajo de su cabecera y hereda su fase/step en el
        # store); emitido antes, quedaría colgado del paso anterior.
        body = content_text(message.get("content"))
        for i, hit in enumerate(ooda_parse.parse_text(body)):
            emit("ooda%d" % i, KIND_OODA, phase=hit["phase"], step=hit["step"],
                 text=hit["description"], summary=one_line(hit["description"]))
        reasoning = message.get("reasoning") or message.get("reasoning_content")
        if isinstance(reasoning, str) and reasoning.strip():
            text, trunc = clip(reasoning)
            emit("reasoning", KIND_REASONING, text=text, truncated=trunc,
                 summary=one_line(text))
        if body.strip():
            text, trunc = clip(body)
            emit("text", KIND_ASSISTANT, text=text, truncated=trunc, summary=one_line(text))
        for tc in parse_tool_calls(message.get("tool_calls")):
            call_id = tc["id"] or "%s:m%s:c%d" % (session_id, mid, tc["index"])
            emit("call%d" % tc["index"], KIND_TOOL_CALL,
                 tool=tc["name"], tool_display=tool_display_name(tc["name"]),
                 category=tool_category(tc["name"]), call_id=call_id, args=tc["args"],
                 summary=summarize_args(tc["args"]))

    elif role == "tool":
        name = message.get("tool_name") or ""
        text, trunc = clip(content_text(message.get("content")))
        emit("result", KIND_TOOL_RESULT, tool=name, tool_display=tool_display_name(name),
             category=tool_category(name), call_id=str(message.get("tool_call_id") or ""),
             text=text, truncated=trunc, summary=one_line(text),
             error=looks_like_error(text))

    return events


def unwrap_result(text: str) -> Any:
    """Decodifica el resultado de una tool (texto) a objeto, quitando envoltorios comunes.

    Hermes guarda el resultado de una tool MCP como texto; según la versión puede ser el JSON
    del dict de la tool, un ``{"result": {...}}`` o la lista de partes de contenido MCP
    (``[{"type":"text","text":"{...}"}]``). Devuelve el dict/lista interior o ``None`` si no
    es JSON. Nunca lanza.
    """
    s = (text or "").strip()
    if not s or s[0] not in "{[":
        return None
    try:
        doc: Any = json.loads(s)
    except (ValueError, TypeError):
        return None
    for _ in range(3):
        if isinstance(doc, dict) and set(doc.keys()) <= {"result", "structuredContent", "content", "isError"}:
            inner = doc.get("structuredContent") or doc.get("result")
            if inner is None and isinstance(doc.get("content"), list):
                inner = doc["content"]
            if inner is None:
                break
            doc = inner
            continue
        if isinstance(doc, list) and doc and all(isinstance(p, dict) for p in doc):
            texts = [p.get("text") for p in doc if p.get("type") == "text" and isinstance(p.get("text"), str)]
            if len(texts) == 1:
                try:
                    doc = json.loads(texts[0])
                    continue
                except (ValueError, TypeError):
                    return {"output": texts[0]}
        if isinstance(doc, str):
            try:
                doc = json.loads(doc)
                continue
            except (ValueError, TypeError):
                return {"output": doc}
        break
    return doc


def tool_output_text(text: str) -> str:
    """La SALIDA útil de una tool: ``output`` de kali_run, ``stdout``/``stderr``, o el texto."""
    doc = unwrap_result(text)
    if isinstance(doc, dict):
        if isinstance(doc.get("output"), str):
            return doc["output"]
        parts = [doc.get(k) for k in ("stdout", "stderr") if isinstance(doc.get(k), str) and doc.get(k)]
        if parts:
            return "\n".join(parts)
    return text or ""


_FAIL_STATUSES = ("error", "failed", "failure", "timeout", "denied", "blocked",
                  "unauthenticated", "unreachable", "out_of_scope", "cancelled")


def looks_like_error(text: str) -> bool:
    """Heurística acotada: ¿la salida de la tool es un error/fallo explícito?

    Solo mira la forma ESTRUCTURADA (dict con ``error``/``isError``/``status`` de fallo, o un
    prefijo ``Error``/``Traceback``) para no marcar como fallo un escaneo cuya salida menciona
    "error" en medio. Un ``returncode`` != 0 de ``kali_run`` NO es fallo (es resultado legítimo
    del comando: nmap sin hallazgos, grep sin match).
    """
    doc = unwrap_result(text)
    if isinstance(doc, dict):
        if doc.get("error") not in (None, "", False):
            return True
        if doc.get("isError") is True or doc.get("is_error") is True:
            return True
        if doc.get("scope_violation") is True or doc.get("timed_out") is True:
            return True
        return str(doc.get("status") or "").lower() in _FAIL_STATUSES
    low = (text or "").lstrip()[:200].lower()
    return low.startswith(("error", "traceback", "exception", "tool error", "failed"))


def messages_to_events(session_id: str, messages: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Aplica :func:`message_to_events` a una secuencia (orden por id de mensaje)."""
    msgs = [m for m in messages if isinstance(m, dict) and m.get("id") is not None]
    try:
        msgs.sort(key=lambda m: (float(m.get("timestamp") or 0), int(m["id"])))
    except (TypeError, ValueError):
        pass
    out: list[dict[str, Any]] = []
    for m in msgs:
        out.extend(message_to_events(session_id, m))
    return out
