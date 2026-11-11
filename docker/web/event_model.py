"""Normalization of Hermes session messages into GUI EVENTS (PURE STDLIB).

Source: ``GET /api/sessions/{id}/messages`` from the Hermes API (``:8642``). Hermes persists
a tool call BEFORE executing it and its result once finished (see
``agent/turn_tool_round.py`` / ``agent/tool_executor.py`` in hermes-agent), so polling
the messages gives almost live EVERYTHING the agent does, whether the session comes from the
API, the TUI, the Webapp or a delegated subagent.

Each message is converted into 0..N events with a stable, GUI-internal schema:

    {key, session_id, message_id, ts, kind, role?, phase?, step?, tool?, tool_display?,
     category?, call_id?, args?, summary?, text?, truncated?}

``kind`` ∈ ``KINDS``. ``key`` is unique and stable (idempotent dedup on re-sync).

Security discipline: ALL content (assistant text, reasoning, args and tool output) is
UNTRUSTED DATA (it may carry prompt-injection or HTML). Here it is only transported, size-
bounded and labeled; it is NEVER interpreted or executed. The frontend always renders it as
text (``textContent``), never as HTML.
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

# Cap on text bytes per event that is PERSISTED (the full output of a scan can be
# huge; the complete raw data lives in the Kali artifacts plane :8901).
TEXT_MAX = 64 * 1024
# Cap on the one-line summary shown in lists/terminal.
SUMMARY_MAX = 240

# Prefixes Hermes uses to name the tools of each MCP server in the profile.
_MCP_PREFIXES = ("mcp_kali_", "mcp_playwright_", "mcp_vulnerator_", "mcp_")

# Args fields that best summarize a call, in order of preference.
_SUMMARY_KEYS = (
    "command", "url", "httpql", "query", "element", "text", "goal", "title",
    "domain", "target", "path", "code", "prompt", "input",
)


def clip(text: Any, limit: int = TEXT_MAX) -> tuple[str, bool]:
    """Coerces to str and bounds to ``limit`` characters. Returns ``(text, truncated)``."""
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
    """Single-line summary (no line breaks), bounded."""
    s, _ = clip(text, limit * 4)
    s = " ".join(s.split())
    return s if len(s) <= limit else s[: limit - 1] + "…"


def tool_display_name(name: str | None) -> str:
    """Short tool name without the MCP server prefix (``mcp_kali_kali_run`` -> ``kali_run``)."""
    n = name or ""
    for prefix in _MCP_PREFIXES:
        if n.startswith(prefix) and len(n) > len(prefix):
            return n[len(prefix):]
    return n


def tool_category(name: str | None) -> str:
    """Tool family for coloring/filtering: shell, browser, web, finding, recon, ..."""
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
    """Plain text of a message ``content`` (str or list of multimodal parts)."""
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
                    parts.append("[image]")
            elif isinstance(part, str):
                parts.append(part)
        return "\n".join(parts)
    return clip(content)[0]


def parse_args(raw: Any) -> Any:
    """Args of a tool-call: JSON-string -> object; if it does not parse, the string is returned."""
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
    """Normalized list ``[{id, name, args}]`` from ``tool_calls`` (JSON str or list).

    Tolerates the OpenAI variants (``{id, function:{name, arguments}}``) and flat ones
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
    """One-line summary of a tool's args (the command, the URL, the query...)."""
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
    """Converts ONE Hermes session message into 0..N GUI events (stable order)."""
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
        # The OODA line goes FIRST: it is the step header. The reasoning of the same message
        # belongs to that step (it is rendered below its header and inherits its phase/step in the
        # store); if emitted earlier, it would end up attached to the previous step.
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
    """Decodes a tool's result (text) into an object, stripping common wrappers.

    Hermes stores the result of an MCP tool as text; depending on the version it can be the JSON
    of the tool's dict, a ``{"result": {...}}`` or the list of MCP content parts
    (``[{"type":"text","text":"{...}"}]``). Returns the inner dict/list or ``None`` if it is not
    JSON. Never raises.
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
    """The useful OUTPUT of a tool: ``output`` from kali_run, ``stdout``/``stderr``, or the text."""
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
    """Bounded heuristic: is the tool's output an explicit error/failure?

    It only looks at the STRUCTURED form (dict with a failure ``error``/``isError``/``status``, or an
    ``Error``/``Traceback`` prefix) so as not to flag as a failure a scan whose output mentions
    "error" in the middle. A ``returncode`` != 0 from ``kali_run`` is NOT a failure (it is a legitimate
    result of the command: nmap with no findings, grep with no match).
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
    """Applies :func:`message_to_events` to a sequence (ordered by message id)."""
    msgs = [m for m in messages if isinstance(m, dict) and m.get("id") is not None]
    try:
        msgs.sort(key=lambda m: (float(m.get("timestamp") or 0), int(m["id"])))
    except (TypeError, ValueError):
        pass
    out: list[dict[str, Any]] = []
    for m in msgs:
        out.extend(message_to_events(session_id, m))
    return out
