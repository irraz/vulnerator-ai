#!/usr/bin/env python3
"""vulnerator-watch — follow in your TERMINAL what Vulnerator is doing, live (PURE STDLIB).

Connects to the ``vulnerator-web`` SSE stream (``/api/stream``) and renders every agent step:
OODA status lines colored by phase, reasoning, every tool-call with its command and its
output, and the result. When the agent CONFIRMS a PoC (``record_finding`` accepted by the
store), it REPLAYS it in the terminal —the typed command and its output with real timings—
and, with ``--record-dir``, saves the ``.cast`` recording (``asciinema play``) and the ``.md`` sheet.

Usage (from the host, with the GUI published on :9100):

    python3 docker/web/vulnerator_watch.py                    # all sessions
    python3 docker/web/vulnerator_watch.py --session <id>     # a single session
    python3 docker/web/vulnerator_watch.py --record-dir ./pocs

or inside the container: ``docker compose exec vulnerator-web python3 vulnerator_watch.py``.

Credentials: ``VULNERATOR_WEB_USER`` / ``VULNERATOR_WEB_PASSWORD`` (by default the dashboard's,
``admin`` / ``vulnerator``) or ``--user`` / ``--password``.

Discipline: everything displayed is UNTRUSTED DATA (tool output, model text). Before writing it
to the terminal the control sequences (ESC, BEL, ...) are NEUTRALIZED, so that malicious output
cannot reprogram your terminal. It only reads; it never acts.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional

import event_model as em

PHASE_COLORS = {"OBSERVE": "38;5;110", "ORIENT": "38;5;169", "DECIDE": "38;5;179",
                "ACT": "38;5;167", "REPORT": "38;5;248"}
CAT_COLORS = {"shell": "1;37", "browser": "38;5;116", "web": "38;5;169", "finding": "1;92",
              "recon": "38;5;110", "tracking": "38;5;244", "subagent": "38;5;179", "tool": "38;5;250"}
FRAME_COLORS = {"ooda": "38;5;174", "cmd": "1;37", "out": "0;37", "note": "38;5;245",
                "ok": "1;92", "err": "1;91"}
OODA_LINE = re.compile(r"^[\s>*_`#]*OODA\s*[—–\-:]+\s*[*_`]*(OBSERVE|ORIENT|DECIDE|ACT|REPORT)\b", re.I)
# C0/C1 controls except \n and \t: replaced with a visible symbol.
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def sanitize(text: Any) -> str:
    """Neutralizes control sequences from untrusted text before printing it."""
    return _CONTROL.sub("·", str(text if text is not None else ""))


class Painter:
    def __init__(self, color: bool) -> None:
        self.color = color

    def __call__(self, code: str, text: str) -> str:
        return "\x1b[%sm%s\x1b[0m" % (code, text) if self.color and code else text


def output_text(text: str) -> str:
    """Useful output of a tool (kali_run's ``output``, stdout/stderr or the text). Delegates to the
    SINGLE unwrapper (``event_model.tool_output_text``) to avoid duplicating the logic."""
    return em.tool_output_text(text)


def fmt_dur(seconds: Optional[float]) -> str:
    if seconds is None:
        return "?"
    s = max(0.0, float(seconds))
    if s < 1:
        return "%dms" % round(s * 1000)
    if s < 60:
        return "%.2fs" % s if s < 10 else "%.1fs" % s
    return "%dm%02ds" % (s // 60, s % 60)


def format_event(ev: dict[str, Any], p: Painter, *, reasoning: bool = True,
                 output_lines: int = 8, tag: str = "", call_ts: Optional[float] = None) -> list[str]:
    """Terminal lines for an event (without trailing newline). Empty list = not shown."""
    kind = ev.get("kind")
    pre = p("38;5;240", tag + " ") if tag else ""
    if kind == "ooda":
        phase = str(ev.get("phase") or "?")
        badge = p("1;" + PHASE_COLORS.get(phase, "37"), "[%s %s]" % (phase, ev.get("step")))
        return ["", pre + badge + " " + p("1;37", sanitize(ev.get("text")))]
    if kind == "user":
        return [pre + p("38;5;169", "operator ▸ ") + sanitize(_one(ev.get("text"), 300))]
    if kind == "reasoning":
        return [pre + p("3;38;5;242", "∴ " + sanitize(_one(ev.get("text"), 260)))] if reasoning else []
    if kind == "assistant":
        body = "\n".join(l for l in str(ev.get("text") or "").splitlines() if not OODA_LINE.match(l)).strip()
        return [pre + p("38;5;252", sanitize(_one(body, 300)))] if body else []
    if kind == "tool.call":
        cat = str(ev.get("category") or "tool")
        name = p(CAT_COLORS.get(cat, "37"), sanitize(ev.get("tool_display") or ev.get("tool")))
        return [pre + p("1;31", "$ ") + name + " " + sanitize(_one(ev.get("summary"), 400))]
    if kind == "tool.result":
        err = bool(ev.get("error"))
        dur = (ev.get("ts") - call_ts) if (call_ts and ev.get("ts")) else None
        head = p("1;91" if err else "1;92", ("✗" if err else "✓") + (" " + fmt_dur(dur) if dur is not None else ""))
        lines = [pre + "  " + head + " " + p("38;5;244", sanitize(ev.get("tool_display") or ev.get("tool")))]
        if output_lines > 0:
            out = output_text(ev.get("text") or "").rstrip("\n").splitlines()
            for ln in out[:output_lines]:
                lines.append(pre + p("38;5;240", "  │ ") + sanitize(ln[:400]))
            if len(out) > output_lines:
                lines.append(pre + p("38;5;240", "  │ … %d more lines" % (len(out) - output_lines)))
        return lines
    return []


def _one(text: Any, limit: int) -> str:
    s = " ".join(str(text or "").split())
    return s if len(s) <= limit else s[: limit - 1] + "…"


def parse_sse(lines: Iterable[str]) -> Iterator[tuple[Optional[str], str, str]]:
    """Minimal SSE parser: yields ``(id, event, data)`` per message (ignores comments)."""
    ev_id: Optional[str] = None
    ev_type = "message"
    data: list[str] = []
    for raw in lines:
        line = raw.rstrip("\r\n")
        if not line:
            if data:
                yield ev_id, ev_type, "\n".join(data)
            ev_type, data = "message", []
            continue
        if line.startswith(":"):
            continue
        field, _, value = line.partition(":")
        value = value[1:] if value.startswith(" ") else value
        if field == "id":
            ev_id = value
        elif field == "event":
            ev_type = value
        elif field == "data":
            data.append(value)


class Watcher:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.base = args.url.rstrip("/")
        token = base64.b64encode(("%s:%s" % (args.user, args.password)).encode()).decode()
        self.auth = {"Authorization": "Basic " + token}
        self.p = Painter(sys.stdout.isatty() and not os.environ.get("NO_COLOR") and not args.no_color)
        self.last_id: Optional[str] = None
        self.call_ts: dict[str, float] = {}
        self.seen_pocs: set[str] = set()

    def _get(self, path: str) -> Any:
        req = urllib.request.Request(self.base + path, headers=self.auth)
        with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310 (operator-supplied URL)
            return json.loads(resp.read().decode("utf-8"))

    def out(self, lines: list[str]) -> None:
        if lines:
            sys.stdout.write("\n".join(lines) + "\n")
            sys.stdout.flush()

    def banner(self) -> None:
        p = self.p
        self.out([p("1;31", "┌──────────────────────────────────────────────────────────┐"),
                  p("1;31", "│") + p("1;37", "  VULNERATOR-AI") + p("38;5;167", " // ") +
                  p("38;5;250", "watch · OODA live                       ") + p("1;31", "│"),
                  p("1;31", "└──────────────────────────────────────────────────────────┘"),
                  p("38;5;244", "  %s%s · Ctrl-C to exit" % (
                      self.base, (" · session " + self.args.session) if self.args.session else ""))])

    def run(self) -> int:
        self.banner()
        after = self._start_cursor()
        backoff = 1.0
        while True:
            try:
                self._stream(after)
                backoff = 1.0
            except KeyboardInterrupt:
                return 0
            except urllib.error.HTTPError as exc:
                if exc.code == 401:
                    self.out([self.p("1;91", "✗ 401: credentials rejected (VULNERATOR_WEB_USER/PASSWORD).")])
                    return 2
                self.out([self.p("38;5;244", "… HTTP %s, retrying" % exc.code)])
            except (urllib.error.URLError, OSError, TimeoutError) as exc:
                self.out([self.p("38;5;244", "… no connection (%s), retrying" % sanitize(exc))])
            if self.last_id:
                after = int(self.last_id)
            try:
                time.sleep(backoff)
            except KeyboardInterrupt:
                return 0
            backoff = min(backoff * 2, 15.0)

    def _start_cursor(self) -> int:
        """Initial cursor: the current end, minus ``--backfill`` events of context."""
        try:
            st = self._get("/api/status")
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                self.out([self.p("1;91", "✗ 401: credentials rejected (VULNERATOR_WEB_USER/PASSWORD).")])
                sys.exit(2)
            raise
        except (urllib.error.URLError, OSError) as exc:
            self.out([self.p("1;91", "✗ cannot reach %s: %s" % (self.base, sanitize(exc)))])
            sys.exit(1)
        top = int(st.get("max_seq") or 0)
        if self.args.backfill <= 0:
            return top
        if self.args.session:
            q = "/api/sessions/%s/events?tail=%d" % (urllib.parse.quote(self.args.session, safe=""),
                                                     self.args.backfill)
            for ev in self._get(q).get("data", []):
                self.handle(ev, replay=False)
            return top
        return max(0, top - self.args.backfill)

    def _stream(self, after: int) -> None:
        q = {"after": str(after)}
        if self.args.session:
            q["session"] = self.args.session
        headers = dict(self.auth, Accept="text/event-stream")
        if self.last_id:
            headers["Last-Event-ID"] = self.last_id
        req = urllib.request.Request(self.base + "/api/stream?" + urllib.parse.urlencode(q), headers=headers)
        with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310
            lines = (raw.decode("utf-8", "replace") for raw in resp)
            for ev_id, ev_type, data in parse_sse(lines):
                if ev_type != "ev":
                    continue
                self.last_id = ev_id or self.last_id
                try:
                    ev = json.loads(data)
                except ValueError:
                    continue
                self.handle(ev, replay=True)

    def handle(self, ev: dict[str, Any], *, replay: bool) -> None:
        if ev.get("kind") == "web.request" and not self.args.web:
            return
        if ev.get("kind") == "web.request":
            x = ev.get("extra") or {}
            self.out([self.p("38;5;169", "  ⇄ ") + sanitize("%s %s → %s" % (x.get("method"), x.get("url"), x.get("status")))])
            return
        if ev.get("kind") == "tool.call" and ev.get("call_id"):
            self.call_ts[ev["call_id"]] = ev.get("ts") or 0
        tag = "" if self.args.session else str(ev.get("session_id") or "")[-6:]
        self.out(format_event(ev, self.p, reasoning=not self.args.no_reasoning,
                              output_lines=self.args.output_lines, tag=tag,
                              call_ts=self.call_ts.get(ev.get("call_id") or "")))
        if replay and ev.get("kind") == "tool.result" and str(ev.get("tool") or "").endswith("record_finding"):
            self.on_finding(ev)

    def on_finding(self, ev: dict[str, Any]) -> None:
        sid, call = ev.get("session_id"), ev.get("call_id")
        if not sid or not call:
            return
        try:
            pocs = self._get("/api/sessions/%s/pocs" % urllib.parse.quote(sid, safe="")).get("data", [])
        except (urllib.error.URLError, OSError, ValueError):
            return
        poc = next((x for x in pocs if x.get("call_id") == call), None)
        if not poc or poc["id"] in self.seen_pocs:
            return
        self.seen_pocs.add(poc["id"])
        p = self.p
        title = sanitize(poc["finding"]["title"])
        if poc.get("store_status") == "rejected":
            self.out([p("1;91", "  ✗ finding rejected by the store: ") + title + p("38;5;244", " — " + sanitize(poc.get("store_error") or ""))])
            return
        if not poc.get("confirmed"):
            self.out([p("38;5;179", "  ◆ finding %s recorded: " % sanitize(poc["finding"].get("state"))) + title])
            return
        bar = "═" * 60
        self.out(["", p("1;92", "╔" + bar + "╗"), p("1;92", "║  PoC CONFIRMED") + "  " + p("1;37", title),
                  p("1;92", "╚" + bar + "╝")])
        if not self.args.no_replay:
            self.play(poc)
        if self.args.record_dir:
            self.record(poc)

    def play(self, poc: dict[str, Any]) -> None:
        speed = max(0.1, self.args.replay_speed)
        prev_t = 0.0
        for fr in poc.get("replay") or []:
            delay = max(0.0, (fr.get("t", 0) - prev_t) / speed)
            prev_t = fr.get("t", 0)
            time.sleep(min(delay, 3.0))
            text = sanitize(fr.get("text"))
            color = FRAME_COLORS.get(fr.get("stream"), "")
            if fr.get("stream") == "cmd" and self.p.color:
                sys.stdout.write("  ")
                for ch in text:
                    sys.stdout.write(self.p(color, ch))
                    sys.stdout.flush()
                    time.sleep(0.012 / speed)
                sys.stdout.write("\n")
            else:
                sys.stdout.write("  " + self.p(color, text) + "\n")
            sys.stdout.flush()
        sys.stdout.write("\n")

    def record(self, poc: dict[str, Any]) -> None:
        base = "/api/sessions/%s/pocs/%s" % (urllib.parse.quote(poc["session_id"], safe=""),
                                             urllib.parse.quote(poc["call_id"], safe=""))
        folder = Path(self.args.record_dir)
        folder.mkdir(parents=True, exist_ok=True)
        stem = re.sub(r"[^A-Za-z0-9_.-]+", "-", poc["finding"]["title"]).strip("-.")[:60] or "poc"
        stem += "__" + re.sub(r"[^A-Za-z0-9_.-]+", "-", poc["call_id"]).strip("-.")[:40]
        for ext in ("cast", "md"):
            req = urllib.request.Request(self.base + base + "." + ext, headers=self.auth)
            try:
                with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310
                    (folder / (stem + "." + ext)).write_bytes(resp.read())
            except (urllib.error.URLError, OSError) as exc:
                self.out([self.p("38;5;244", "  (could not save .%s: %s)" % (ext, sanitize(exc)))])
                return
        self.out([self.p("38;5;244", "  ⏺ recorded to %s/%s.{cast,md}  ·  asciinema play %s/%s.cast" % (
            folder, stem, folder, stem))])


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="vulnerator-watch", description=__doc__.split("\n\n")[0])
    ap.add_argument("--url", default=os.environ.get("VULNERATOR_WEB_URL", "http://localhost:9100"))
    ap.add_argument("--user", default=os.environ.get("VULNERATOR_WEB_USER", "admin"))
    ap.add_argument("--password", default=os.environ.get("VULNERATOR_WEB_PASSWORD", "vulnerator"))
    ap.add_argument("--session", help="follow only this session")
    ap.add_argument("--backfill", type=int, default=30, help="previous context events (0 = none)")
    ap.add_argument("--output-lines", type=int, default=8, help="output lines per tool (0 = hide)")
    ap.add_argument("--no-reasoning", action="store_true", help="hide the reasoning")
    ap.add_argument("--web", action="store_true", help="also show Caido's web traffic")
    ap.add_argument("--no-replay", action="store_true", help="do not replay the confirmed PoCs")
    ap.add_argument("--replay-speed", type=float, default=1.0)
    ap.add_argument("--record-dir", help="save here the .cast and .md of each confirmed PoC")
    ap.add_argument("--no-color", action="store_true")
    return ap


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return Watcher(args).run()
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
