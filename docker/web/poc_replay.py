"""PoC replay: how the agent reached a finding and how it reproduced it (PURE STDLIB).

Input: the normalized events of ONE session (``trace_store.session_events``), in order.
Output: one record per ``record_finding`` call with:

  - ``finding``: the fields of the finding as the agent recorded them (title, state,
    phase, target, technique, evidence...), and whether the store ACCEPTED it
    (``status: recorded``) or REJECTED it (e.g. a ``confirmed`` without reproducible evidence).
  - ``chain``: the reasoning chain that precedes it — OODA status lines, reasoning,
    assistant comments and each tool-call with its result — from the start of the session
    (bounded to the last ``CHAIN_MAX`` steps, with a count of omitted ones).
  - ``reproduction``: the EXACT command from the evidence and its verbatim output. If that
    command was actually run in the session (``kali_run``/``kali_exec``), the real execution
    (output, duration, returncode) is LINKED instead of relying solely on what the agent
    pasted into the evidence.
  - ``replay``: a terminal script ``[{t, stream, text}]`` that the GUI plays back step by
    step, exportable as an asciinema v2 recording (``to_asciicast``) and as Markdown
    (``to_markdown``) to attach to the report.

Discipline: all content is UNTRUSTED DATA; here it is only ordered, bounded and formatted as
text. Nothing is executed: the "replay" REPLAYS what was recorded, it does not re-execute.
"""

from __future__ import annotations

import json
from typing import Any, Iterable, Optional

import event_model as em

# Maximum chain steps returned (the most recent ones before the finding).
CHAIN_MAX = 160
# Text clipping for each chain step (reasoning/comment/output).
STEP_TEXT_MAX = 1500
# Maximum output lines in the replay script and the width of each one.
REPLAY_MAX_LINES = 400
REPLAY_LINE_MAX = 400
# Maximum playback time for the output (the real duration is compressed if longer).
REPLAY_OUTPUT_SECONDS = 6.0
# Last OODA lines that open the replay (immediate context of the PoC).
REPLAY_OODA_LEAD = 6


def is_record_finding(ev: dict[str, Any]) -> bool:
    return ev.get("kind") == em.KIND_TOOL_CALL and str(ev.get("tool") or "").endswith("record_finding")


def _norm_cmd(cmd: Any) -> str:
    if isinstance(cmd, list):
        cmd = " ".join(str(c) for c in cmd)
    return " ".join(str(cmd or "").split())


def _clip(text: Any, limit: int = STEP_TEXT_MAX) -> str:
    s, trunc = em.clip(text, limit)
    return s + ("\n…[clipped]" if trunc else "")


def _result_status(result_ev: Optional[dict[str, Any]]) -> Optional[str]:
    """``recorded`` / ``rejected`` / None (no result yet) for a record_finding."""
    if result_ev is None:
        return None
    doc = em.unwrap_result(result_ev.get("text") or "")
    if isinstance(doc, dict):
        status = str(doc.get("status") or "").lower()
        if status == "recorded":
            return "recorded"
        if status == "error" or doc.get("error"):
            return "rejected"
    return "rejected" if result_ev.get("error") else "recorded"


def _result_error(result_ev: Optional[dict[str, Any]]) -> Optional[str]:
    if result_ev is None:
        return None
    doc = em.unwrap_result(result_ev.get("text") or "")
    if isinstance(doc, dict) and doc.get("error"):
        return em.one_line(doc.get("error"), 400)
    return None


def _returncode(text: str) -> Optional[int]:
    doc = em.unwrap_result(text or "")
    if isinstance(doc, dict):
        rc = doc.get("returncode", doc.get("exit_code"))
        if isinstance(rc, int) and not isinstance(rc, bool):
            return rc
    return None


def _step(ev: dict[str, Any], result: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """A chain step (compact, bounded form)."""
    kind = ev.get("kind")
    step: dict[str, Any] = {
        "seq": ev.get("seq"), "ts": ev.get("ts"), "kind": kind,
        "phase": ev.get("phase"), "step": ev.get("step"),
    }
    if kind == em.KIND_OODA:
        step["text"] = ev.get("text") or ""
    elif kind in (em.KIND_REASONING, em.KIND_ASSISTANT, em.KIND_USER):
        step["text"] = _clip(ev.get("text"))
    elif kind == em.KIND_TOOL_CALL:
        step.update({
            "tool": ev.get("tool_display") or ev.get("tool"), "category": ev.get("category"),
            "call_id": ev.get("call_id"), "summary": ev.get("summary") or "",
        })
        if result is not None:
            out = em.tool_output_text(result.get("text") or "")
            step["result"] = {
                "status": "error" if result.get("error") else "ok",
                "summary": em.one_line(out, 300),
                "duration": _dur(ev, result),
            }
    return step


def _dur(call: Optional[dict[str, Any]], result: Optional[dict[str, Any]]) -> Optional[float]:
    try:
        return max(0.0, float(result["ts"]) - float(call["ts"]))  # type: ignore[index]
    except (TypeError, KeyError, ValueError):
        return None


def _find_execution(
    command: str, calls: list[dict[str, Any]], results: dict[str, dict[str, Any]]
) -> Optional[tuple[dict[str, Any], Optional[dict[str, Any]]]]:
    """The REAL execution (most recent) whose command matches the one in the evidence."""
    target = _norm_cmd(command)
    if not target:
        return None
    best = None
    for call in calls:
        if call.get("category") != "shell":
            continue
        args = call.get("args") if isinstance(call.get("args"), dict) else {}
        cmd = _norm_cmd(args.get("command"))
        if not cmd:
            continue
        if cmd == target or (len(target) >= 8 and (target in cmd or cmd in target)):
            best = call
    if best is None:
        return None
    return best, results.get(best.get("call_id") or "")


def build_pocs(events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Builds one PoC record per ``record_finding`` in the session (order of appearance)."""
    evs = sorted((e for e in events if isinstance(e, dict)), key=lambda e: e.get("seq") or 0)
    results: dict[str, dict[str, Any]] = {}
    for ev in evs:
        if ev.get("kind") == em.KIND_TOOL_RESULT and ev.get("call_id"):
            results[ev["call_id"]] = ev

    pocs: list[dict[str, Any]] = []
    chain: list[dict[str, Any]] = []
    calls: list[dict[str, Any]] = []
    for ev in evs:
        kind = ev.get("kind")
        if kind == em.KIND_TOOL_RESULT or kind == em.KIND_WEB:
            continue  # results are attached to their call
        if is_record_finding(ev):
            pocs.append(_build_one(ev, results, chain, calls))
        if kind == em.KIND_TOOL_CALL:
            calls.append(ev)
            chain.append(_step(ev, results.get(ev.get("call_id") or "")))
        elif kind in (em.KIND_OODA, em.KIND_REASONING, em.KIND_ASSISTANT, em.KIND_USER):
            chain.append(_step(ev))
    return pocs


def _build_one(
    call: dict[str, Any],
    results: dict[str, dict[str, Any]],
    chain: list[dict[str, Any]],
    calls: list[dict[str, Any]],
) -> dict[str, Any]:
    args = call.get("args") if isinstance(call.get("args"), dict) else {}
    result = results.get(call.get("call_id") or "")
    evidence = args.get("evidence") if isinstance(args.get("evidence"), dict) else {}
    finding = {
        "title": str(args.get("title") or "(untitled)"),
        "state": str(args.get("state") or ""),
        "phase": args.get("phase") or None,
        "target": args.get("target") or None,
        "technique_id": args.get("technique_id") or None,
        "confidence": args.get("confidence") or None,
        "engagement_id": args.get("engagement_id") or None,
        "evidence": evidence or None,
        "change": args.get("change") if isinstance(args.get("change"), dict) else None,
    }
    store_status = _result_status(result)

    command = evidence.get("command") if evidence else None
    linked = _find_execution(command, calls, results) if command else None
    reproduction: dict[str, Any] = {
        "command": _norm_cmd(command) if command else None,
        "evidence_output": evidence.get("output") if isinstance(evidence.get("output"), str) else None,
        "artifact_ref": evidence.get("artifact_ref") if isinstance(evidence.get("artifact_ref"), dict) else None,
        "execution": None,
    }
    if linked is not None:
        exe_call, exe_result = linked
        out_text = em.tool_output_text(exe_result.get("text") or "") if exe_result else None
        reproduction["execution"] = {
            "seq": exe_call.get("seq"),
            "call_id": exe_call.get("call_id"),
            "tool": exe_call.get("tool_display") or exe_call.get("tool"),
            "command": _norm_cmd((exe_call.get("args") or {}).get("command")),
            "started_at": exe_call.get("ts"),
            "duration": _dur(exe_call, exe_result),
            "returncode": _returncode(exe_result.get("text") or "") if exe_result else None,
            "output": out_text,
            "output_truncated": bool(exe_result.get("truncated")) if exe_result else False,
            "phase": exe_call.get("phase"), "step": exe_call.get("step"),
        }

    omitted = max(0, len(chain) - CHAIN_MAX)
    poc = {
        "id": "%s:%s" % (call.get("session_id"), call.get("call_id")),
        "session_id": call.get("session_id"),
        "call_id": call.get("call_id"),
        "seq": call.get("seq"),
        "ts": call.get("ts"),
        "phase": call.get("phase"),
        "step": call.get("step"),
        "finding": finding,
        "store_status": store_status,
        "store_error": _result_error(result),
        "confirmed": finding["state"] == "confirmed" and store_status != "rejected",
        "reproduction": reproduction,
        "chain": chain[omitted:],
        "chain_omitted": omitted,
        "ooda_path": [s for s in chain if s["kind"] == em.KIND_OODA],
    }
    poc["replay"] = build_replay(poc)
    return poc


def _split_lines(text: str) -> list[str]:
    lines = (text or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")
    while lines and not lines[-1].strip():
        lines.pop()
    out = []
    for ln in lines[:REPLAY_MAX_LINES]:
        out.append(ln if len(ln) <= REPLAY_LINE_MAX else ln[: REPLAY_LINE_MAX - 1] + "…")
    if len(lines) > REPLAY_MAX_LINES:
        out.append("… [%d more lines in the full evidence]" % (len(lines) - REPLAY_MAX_LINES))
    return out


def build_replay(poc: dict[str, Any]) -> list[dict[str, Any]]:
    """Terminal script ``[{t, stream, text}]`` (``t`` in seconds from the start)."""
    frames: list[dict[str, Any]] = []
    t = 0.0

    def add(stream: str, text: str, dt: float) -> None:
        nonlocal t
        t += dt
        frames.append({"t": round(t, 3), "stream": stream, "text": text})

    f = poc["finding"]
    add("note", "# PoC · %s" % f["title"], 0.0)
    if f.get("target"):
        add("note", "# target: %s" % f["target"], 0.15)
    for s in poc["ooda_path"][-REPLAY_OODA_LEAD:]:
        add("ooda", "OODA — %s (step %s): %s" % (s.get("phase"), s.get("step"), s.get("text")), 0.45)

    rep = poc["reproduction"]
    exe = rep.get("execution")
    command = (exe or {}).get("command") or rep.get("command")
    output = (exe or {}).get("output")
    if output is None:
        output = rep.get("evidence_output")
    if command:
        add("cmd", "$ " + command, 0.6)
        lines = _split_lines(output or "")
        real = (exe or {}).get("duration") or 0.0
        span = min(max(real, 0.8), REPLAY_OUTPUT_SECONDS)
        dt = span / max(1, len(lines))
        for ln in lines:
            add("out", ln, dt)
        if exe and exe.get("returncode") is not None:
            add("note", "# exit %s · %.2fs real" % (exe["returncode"], real), 0.2)
    elif rep.get("artifact_ref"):
        ref = rep["artifact_ref"]
        add("note", "# evidence in artifact: %s/%s" % (ref.get("execution_id"), ref.get("name")), 0.4)
    else:
        add("note", "# no reproducible command in the evidence", 0.4)

    if poc["store_status"] == "rejected":
        add("err", "✗ record_finding rejected: %s" % (poc.get("store_error") or "insufficient evidence"), 0.5)
    elif poc["store_status"] == "recorded":
        add("ok", "✓ finding %s recorded: %s" % (f["state"] or "?", f["title"]), 0.5)
    else:
        add("note", "… recording finding", 0.5)
    return frames


def to_asciicast(poc: dict[str, Any], width: int = 120, height: int = 34) -> str:
    """Asciinema v2 recording (``asciinema play poc.cast``) of the PoC replay."""
    colors = {"ooda": "\x1b[38;5;174m", "cmd": "\x1b[1;37m", "out": "\x1b[0;37m",
              "note": "\x1b[38;5;245m", "ok": "\x1b[1;32m", "err": "\x1b[1;31m"}
    header = {
        "version": 2, "width": width, "height": height,
        "timestamp": int(poc.get("ts") or 0),
        "title": "Vulnerator-AI PoC: %s" % poc["finding"]["title"],
        "env": {"TERM": "xterm-256color", "SHELL": "/bin/sh"},
    }
    lines = [json.dumps(header, ensure_ascii=False)]
    for fr in poc["replay"]:
        text = fr["text"].replace("\x1b", "␛")  # never re-inject raw escape sequences
        out = "%s%s\x1b[0m\r\n" % (colors.get(fr["stream"], ""), text)
        lines.append(json.dumps([fr["t"], "o", out], ensure_ascii=False))
    return "\n".join(lines) + "\n"


def _fence(text: str) -> str:
    longest = 0
    run = 0
    for ch in text:
        run = run + 1 if ch == "`" else 0
        longest = max(longest, run)
    return "`" * max(3, longest + 1)


def to_markdown(poc: dict[str, Any]) -> str:
    """Markdown sheet of the PoC (OODA chain + reproduction) to attach to the report."""
    f = poc["finding"]
    rep = poc["reproduction"]
    exe = rep.get("execution") or {}
    out = ["# PoC — %s" % f["title"], ""]
    meta = [
        ("State", f.get("state")), ("Record", poc.get("store_status")),
        ("Target", f.get("target")), ("Technique", f.get("technique_id")),
        ("Confidence", f.get("confidence")), ("Engagement", f.get("engagement_id")),
        ("OODA phase", "%s (step %s)" % (poc.get("phase"), poc.get("step")) if poc.get("phase") else None),
        ("Session", poc.get("session_id")),
    ]
    for k, v in meta:
        if v:
            out.append("- **%s:** %s" % (k, v))
    if poc.get("store_error"):
        out.append("- **Rejection reason:** %s" % poc["store_error"])
    out += ["", "## How it got here (OODA path)", ""]
    if poc["ooda_path"]:
        for s in poc["ooda_path"]:
            out.append("%s. **%s** — %s" % (s.get("step"), s.get("phase"), s.get("text")))
    else:
        out.append("_The agent did not emit OODA status lines in this session._")
    out += ["", "## Executed steps", ""]
    for s in poc["chain"]:
        if s["kind"] == em.KIND_TOOL_CALL:
            res = s.get("result") or {}
            dur = res.get("duration")
            out.append("- `%s` %s%s%s" % (
                s.get("tool"), em.one_line(s.get("summary"), 160).replace("`", "'"),
                " — %s" % res.get("status") if res else " — no result",
                " (%.2fs)" % dur if isinstance(dur, (int, float)) else "",
            ))
    if poc.get("chain_omitted"):
        out.append("- _(%d earlier steps omitted)_" % poc["chain_omitted"])
    out += ["", "## Reproduction", ""]
    command = exe.get("command") or rep.get("command")
    if command:
        fence = _fence(command)
        out += ["Exact command:", "", fence + "sh", command, fence, ""]
        output = exe.get("output") if exe.get("output") is not None else rep.get("evidence_output")
        if output:
            fence = _fence(output)
            src = "real output of the linked execution" if exe else "output pasted in the evidence"
            out += ["Output (%s):" % src, "", fence, output.rstrip("\n"), fence, ""]
        if exe:
            out.append("_Executed with `%s` · exit %s · %.2fs._" % (
                exe.get("tool"), exe.get("returncode"), exe.get("duration") or 0.0))
    elif rep.get("artifact_ref"):
        ref = rep["artifact_ref"]
        out.append("Evidence in artifact `%s/%s` (Kali data plane, `:8901`)." % (
            ref.get("execution_id"), ref.get("name")))
    else:
        out.append("_No reproducible command in the evidence._")
    out.append("")
    return "\n".join(out)
