"""Trace store for the Vulnerator GUI (PURE STDLIB: ``sqlite3``).

It is the durable memory of the ``vulnerator-web`` service and, at the same time, its event BUS:

  - ``sessions``: metadata of each Hermes session (title, source, tokens, cost, current
    OODA phase...). Includes delegated subagents (``parent_id``).
  - ``events``: each normalized event (see ``event_model``) with a GLOBAL monotonic ``seq``
    (``INTEGER PRIMARY KEY AUTOINCREMENT``). That ``seq`` is the cursor of the live stream
    toward the browser: a client that reconnects asks for ``seq > last`` and loses nothing
    (free resumption, no in-memory queue).
  - ``spans``: ONE row per tool-call (``session_id`` + ``call_id``) with start, end,
    duration, status and OODA phase. It is the "Langfuse-like" view: which tools it calls,
    with what args, how long they take and whether they fail. The start comes from the
    assistant message that requests the tool (Hermes persists it BEFORE executing it) and
    the end from the ``tool`` message with the result; a tool in progress stays ``running``.

Idempotent: re-syncing the same messages does not duplicate anything (``key`` UNIQUE in
``events`` + ``seen_messages`` table).

Why SQLite and not Langfuse: operator's decision (own traces, lightweight, offline, with no
extra service or credentials). The file lives in a named volume of the service.

Discipline: event content is UNTRUSTED DATA; here it is only stored with bound parameters
(never SQL composed with data) and returned as is.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from typing import Any, Iterable, Optional

import event_model as em

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    parent_id TEXT,
    title TEXT,
    source TEXT,
    model TEXT,
    started_at REAL,
    ended_at REAL,
    end_reason TEXT,
    last_active REAL,
    message_count INTEGER,
    tool_call_count INTEGER,
    input_tokens INTEGER,
    output_tokens INTEGER,
    cost_usd REAL,
    preview TEXT,
    last_phase TEXT,
    last_step INTEGER,
    updated_at REAL
);
CREATE TABLE IF NOT EXISTS events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL UNIQUE,
    session_id TEXT,
    message_id INTEGER,
    ts REAL,
    kind TEXT NOT NULL,
    role TEXT,
    phase TEXT,
    step INTEGER,
    tool TEXT,
    tool_display TEXT,
    category TEXT,
    call_id TEXT,
    summary TEXT,
    text TEXT,
    truncated INTEGER DEFAULT 0,
    error INTEGER DEFAULT 0,
    args TEXT,
    extra TEXT
);
CREATE INDEX IF NOT EXISTS events_session ON events(session_id, seq);
CREATE INDEX IF NOT EXISTS events_kind ON events(kind, seq);
CREATE TABLE IF NOT EXISTS spans (
    session_id TEXT NOT NULL,
    call_id TEXT NOT NULL,
    tool TEXT,
    tool_display TEXT,
    category TEXT,
    summary TEXT,
    started_at REAL,
    ended_at REAL,
    duration REAL,
    status TEXT,
    phase TEXT,
    step INTEGER,
    result_preview TEXT,
    call_seq INTEGER,
    result_seq INTEGER,
    PRIMARY KEY (session_id, call_id)
);
CREATE TABLE IF NOT EXISTS seen_messages (
    session_id TEXT NOT NULL,
    message_id INTEGER NOT NULL,
    PRIMARY KEY (session_id, message_id)
);
"""

# Hermes session fields (``_session_response``) -> local column.
_SESSION_FIELDS = {
    "parent_session_id": "parent_id", "title": "title", "source": "source", "model": "model",
    "started_at": "started_at", "ended_at": "ended_at", "end_reason": "end_reason",
    "last_active": "last_active", "message_count": "message_count",
    "tool_call_count": "tool_call_count", "input_tokens": "input_tokens",
    "output_tokens": "output_tokens", "preview": "preview",
}

_EVENT_COLS = (
    "key", "session_id", "message_id", "ts", "kind", "role", "phase", "step", "tool",
    "tool_display", "category", "call_id", "summary", "text", "truncated", "error", "args",
    "extra",
)

# Size of the result preview stored in the span (the full text is in events).
_SPAN_PREVIEW_MAX = 600


def _num(value: Any) -> Optional[float]:
    try:
        return None if value is None else float(value)
    except (TypeError, ValueError):
        return None


class TraceStore:
    """Thread-safe facade over a SQLite connection (WAL)."""

    def __init__(self, path: str = ":memory:") -> None:
        self._lock = threading.RLock()
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        if path != ":memory:":
            self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.executescript(SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # ------------------------------------------------------------------ sessions
    def upsert_session(self, meta: dict[str, Any]) -> bool:
        """Inserts/updates the session with Hermes metadata. True if anything changed."""
        sid = meta.get("id")
        if not isinstance(sid, str) or not sid:
            return False
        cols: dict[str, Any] = {}
        for src, dst in _SESSION_FIELDS.items():
            if src in meta:
                cols[dst] = meta[src]
        cost = meta.get("actual_cost_usd")
        if cost is None:
            cost = meta.get("estimated_cost_usd")
        if cost is not None:
            cols["cost_usd"] = _num(cost)
        with self._lock:
            row = self._db.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
            if row is None:
                cols["id"] = sid
                cols["updated_at"] = time.time()
                names = ",".join(cols)
                marks = ",".join("?" for _ in cols)
                self._db.execute("INSERT INTO sessions (%s) VALUES (%s)" % (names, marks),
                                 tuple(cols.values()))
                return True
            changed = {k: v for k, v in cols.items() if row[k] != v}
            if not changed:
                return False
            changed["updated_at"] = time.time()
            sets = ",".join("%s=?" % k for k in changed)
            self._db.execute("UPDATE sessions SET %s WHERE id=?" % sets,
                             (*changed.values(), sid))
            return True

    def session(self, session_id: str) -> Optional[dict[str, Any]]:
        with self._lock:
            row = self._db.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
        return dict(row) if row else None

    def list_sessions(self, limit: int = 100) -> list[dict[str, Any]]:
        """Sessions by recent activity, with counters of tools/findings/failures."""
        with self._lock:
            rows = self._db.execute(
                """
                SELECT s.*,
                  (SELECT COUNT(*) FROM spans p WHERE p.session_id=s.id) AS spans,
                  (SELECT COUNT(*) FROM spans p WHERE p.session_id=s.id AND p.status='running') AS running,
                  (SELECT COUNT(*) FROM spans p WHERE p.session_id=s.id AND p.status='error') AS errors,
                  (SELECT COUNT(*) FROM events e WHERE e.session_id=s.id AND e.kind='tool.call'
                     AND e.category='finding' AND e.tool LIKE '%record_finding') AS findings,
                  (SELECT MAX(seq) FROM events e WHERE e.session_id=s.id) AS last_seq
                FROM sessions s
                ORDER BY COALESCE(s.last_active, s.started_at, 0) DESC
                LIMIT ?
                """,
                (max(1, min(int(limit), 1000)),),
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------ messages
    def seen_message_ids(self, session_id: str) -> set[int]:
        with self._lock:
            rows = self._db.execute(
                "SELECT message_id FROM seen_messages WHERE session_id=?", (session_id,)
            ).fetchall()
        return {r[0] for r in rows}

    def ingest_messages(self, session_id: str, messages: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
        """Ingests NEW messages of a session and returns the inserted events (with ``seq``).

        Tags each event with the current OODA phase/step (the last status line seen in the
        session) and maintains the spans: ``tool.call`` opens a ``running`` span; ``tool.result``
        closes it with duration and ``ok``/``error`` status.
        """
        msgs = []
        for m in messages:
            if not isinstance(m, dict):
                continue
            try:
                mid = int(m.get("id"))
            except (TypeError, ValueError):
                continue
            msgs.append((float(m.get("timestamp") or 0), mid, m))
        msgs.sort(key=lambda t: (t[1]))
        inserted: list[dict[str, Any]] = []
        with self._lock:
            seen = self.seen_message_ids(session_id)
            sess = self._db.execute(
                "SELECT last_phase, last_step FROM sessions WHERE id=?", (session_id,)
            ).fetchone()
            if sess is None:
                self._db.execute("INSERT INTO sessions (id, updated_at) VALUES (?, ?)",
                                 (session_id, time.time()))
                phase, step = None, None
            else:
                phase, step = sess["last_phase"], sess["last_step"]
            self._db.execute("BEGIN")
            try:
                for _ts, mid, msg in msgs:
                    if mid in seen:
                        continue
                    for ev in em.message_to_events(session_id, msg):
                        if ev["kind"] == em.KIND_OODA:
                            phase, step = ev.get("phase"), ev.get("step")
                        else:
                            ev.setdefault("phase", phase)
                            ev.setdefault("step", step)
                        seq = self._insert_event(ev)
                        if seq is None:
                            continue
                        ev["seq"] = seq
                        self._update_span(ev)
                        inserted.append(ev)
                    self._db.execute(
                        "INSERT OR IGNORE INTO seen_messages (session_id, message_id) VALUES (?, ?)",
                        (session_id, mid),
                    )
                    seen.add(mid)
                self._db.execute(
                    "UPDATE sessions SET last_phase=?, last_step=? WHERE id=?",
                    (phase, step, session_id),
                )
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
        return inserted

    def _insert_event(self, ev: dict[str, Any]) -> Optional[int]:
        row = []
        for col in _EVENT_COLS:
            val = ev.get(col)
            if col in ("args", "extra"):
                val = None if val is None else json.dumps(val, ensure_ascii=False, default=str)
            elif col in ("truncated", "error"):
                val = 1 if val else 0
            row.append(val)
        cur = self._db.execute(
            "INSERT OR IGNORE INTO events (%s) VALUES (%s)"
            % (",".join(_EVENT_COLS), ",".join("?" for _ in _EVENT_COLS)),
            row,
        )
        if cur.rowcount == 0:
            return None
        return int(cur.lastrowid)

    def _update_span(self, ev: dict[str, Any]) -> None:
        kind = ev.get("kind")
        sid = ev.get("session_id")
        call_id = ev.get("call_id")
        if kind not in (em.KIND_TOOL_CALL, em.KIND_TOOL_RESULT) or not sid or not call_id:
            return
        if kind == em.KIND_TOOL_CALL:
            self._db.execute(
                """
                INSERT INTO spans (session_id, call_id, tool, tool_display, category, summary,
                                   started_at, status, phase, step, call_seq)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'running', ?, ?, ?)
                ON CONFLICT(session_id, call_id) DO UPDATE SET
                  tool=excluded.tool, tool_display=excluded.tool_display,
                  category=excluded.category, summary=excluded.summary,
                  started_at=excluded.started_at, phase=excluded.phase, step=excluded.step,
                  call_seq=excluded.call_seq,
                  duration=CASE WHEN spans.ended_at IS NOT NULL
                                THEN MAX(0, spans.ended_at - excluded.started_at) END
                """,
                (sid, call_id, ev.get("tool"), ev.get("tool_display"), ev.get("category"),
                 ev.get("summary"), ev.get("ts"), ev.get("phase"), ev.get("step"), ev.get("seq")),
            )
            return
        status = "error" if ev.get("error") else "ok"
        preview = em.one_line(ev.get("text") or "", _SPAN_PREVIEW_MAX)
        self._db.execute(
            """
            INSERT INTO spans (session_id, call_id, tool, tool_display, category, ended_at,
                               status, result_preview, result_seq, phase, step)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(session_id, call_id) DO UPDATE SET
              ended_at=excluded.ended_at, status=excluded.status,
              result_preview=excluded.result_preview, result_seq=excluded.result_seq,
              duration=CASE WHEN spans.started_at IS NOT NULL
                            THEN MAX(0, excluded.ended_at - spans.started_at) END
            """,
            (sid, call_id, ev.get("tool"), ev.get("tool_display"), ev.get("category"),
             ev.get("ts"), status, preview, ev.get("seq"), ev.get("phase"), ev.get("step")),
        )

    # ------------------------------------------------------------------ web traffic
    def ingest_web(self, entries: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
        """Ingests entries from Caido's history as ``web.request`` events (dedup by id)."""
        inserted = []
        with self._lock:
            self._db.execute("BEGIN")
            try:
                for entry in entries:
                    if not isinstance(entry, dict) or entry.get("id") in (None, ""):
                        continue
                    ev = web_entry_to_event(entry)
                    seq = self._insert_event(ev)
                    if seq is None:
                        continue
                    ev["seq"] = seq
                    inserted.append(ev)
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
        return inserted

    # ------------------------------------------------------------------ reading
    def max_seq(self) -> int:
        with self._lock:
            row = self._db.execute("SELECT COALESCE(MAX(seq), 0) FROM events").fetchone()
        return int(row[0])

    def events(
        self,
        after: int = 0,
        *,
        session_id: Optional[str] = None,
        kinds: Optional[Iterable[str]] = None,
        limit: int = 500,
        text_limit: Optional[int] = None,
    ) -> list[dict[str, Any]]:
        """Events with ``seq > after`` (ascending order), filterable by session and kind."""
        sql = "SELECT * FROM events WHERE seq > ?"
        params: list[Any] = [int(after)]
        if session_id:
            sql += " AND session_id = ?"
            params.append(session_id)
        kinds = [k for k in (kinds or []) if k in em.KINDS]
        if kinds:
            sql += " AND kind IN (%s)" % ",".join("?" for _ in kinds)
            params.extend(kinds)
        sql += " ORDER BY seq ASC LIMIT ?"
        params.append(max(1, min(int(limit), 5000)))
        with self._lock:
            rows = self._db.execute(sql, params).fetchall()
        return [row_to_event(r, text_limit) for r in rows]

    def tail_events(self, session_id: Optional[str] = None, limit: int = 400, *,
                    kinds: Optional[Iterable[str]] = None,
                    text_limit: Optional[int] = None) -> list[dict[str, Any]]:
        """The last ``limit`` events (ascending order), filterable by session and/or kind. The
        clipping is done in SQL (``ORDER BY seq DESC LIMIT``), without bringing the whole table into memory."""
        where: list[str] = []
        params: list[Any] = []
        if session_id:
            where.append("session_id = ?")
            params.append(session_id)
        kinds = [k for k in (kinds or []) if k in em.KINDS]
        if kinds:
            where.append("kind IN (%s)" % ",".join("?" for _ in kinds))
            params.extend(kinds)
        inner = "SELECT * FROM events"
        if where:
            inner += " WHERE " + " AND ".join(where)
        inner += " ORDER BY seq DESC LIMIT ?"
        params.append(max(1, min(int(limit), 5000)))
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM (%s) ORDER BY seq ASC" % inner, params
            ).fetchall()
        return [row_to_event(r, text_limit) for r in rows]

    def event(self, seq: int) -> Optional[dict[str, Any]]:
        with self._lock:
            row = self._db.execute("SELECT * FROM events WHERE seq=?", (int(seq),)).fetchone()
        return row_to_event(row) if row else None

    def session_events(self, session_id: str) -> list[dict[str, Any]]:
        """ALL events of a session (full text) — input for the PoC replay."""
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM events WHERE session_id=? ORDER BY seq ASC", (session_id,)
            ).fetchall()
        return [row_to_event(r) for r in rows]

    def spans(self, session_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM spans WHERE session_id=? "
                "ORDER BY COALESCE(started_at, ended_at), call_seq",
                (session_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def trace_summary(self, session_id: str) -> dict[str, Any]:
        """Aggregates per tool (calls, total/avg/max time, errors) + totals."""
        spans = self.spans(session_id)
        per_tool: dict[str, dict[str, Any]] = {}
        total_time = 0.0
        for sp in spans:
            name = sp.get("tool_display") or sp.get("tool") or "?"
            agg = per_tool.setdefault(name, {
                "tool": name, "category": sp.get("category"), "calls": 0, "errors": 0,
                "running": 0, "total": 0.0, "max": 0.0,
            })
            agg["calls"] += 1
            if sp.get("status") == "error":
                agg["errors"] += 1
            if sp.get("status") == "running":
                agg["running"] += 1
            dur = sp.get("duration")
            if isinstance(dur, (int, float)):
                agg["total"] += dur
                agg["max"] = max(agg["max"], dur)
                total_time += dur
        for agg in per_tool.values():
            done = agg["calls"] - agg["running"]
            agg["avg"] = (agg["total"] / done) if done else 0.0
        starts = [s["started_at"] for s in spans if s.get("started_at")]
        ends = [s["ended_at"] for s in spans if s.get("ended_at")]
        return {
            "session_id": session_id,
            "spans": len(spans),
            "errors": sum(1 for s in spans if s.get("status") == "error"),
            "running": sum(1 for s in spans if s.get("status") == "running"),
            "tool_time": total_time,
            "first_start": min(starts) if starts else None,
            "last_end": max(ends) if ends else None,
            "tools": sorted(per_tool.values(), key=lambda a: a["total"], reverse=True),
        }


def row_to_event(row: sqlite3.Row, text_limit: Optional[int] = None) -> dict[str, Any]:
    """Row from ``events`` -> event dict (args/extra decoded, text optionally bounded)."""
    ev = {k: row[k] for k in row.keys()}
    for col in ("args", "extra"):
        raw = ev.get(col)
        if raw is not None:
            try:
                ev[col] = json.loads(raw)
            except (ValueError, TypeError):
                pass
    ev["truncated"] = bool(ev.get("truncated"))
    ev["error"] = bool(ev.get("error"))
    if text_limit is not None and isinstance(ev.get("text"), str) and len(ev["text"]) > text_limit:
        ev["text"] = ev["text"][:text_limit]
        ev["truncated"] = True
        ev["clipped"] = True
    return {k: v for k, v in ev.items() if v is not None}


def _caido_ts(value: Any) -> float:
    """Caido's ``createdAt`` (epoch ms or ISO-8601) -> epoch seconds; 0 if not understood."""
    if isinstance(value, (int, float)):
        return float(value) / (1000.0 if value > 1e11 else 1.0)
    if isinstance(value, str) and value:
        if value.isdigit():
            return _caido_ts(int(value))
        from datetime import datetime
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return 0.0
    return 0.0


def web_entry_to_event(entry: dict[str, Any]) -> dict[str, Any]:
    """Entry from ``caido_client.search_history`` -> GUI ``web.request`` event."""
    resp = entry.get("response") if isinstance(entry.get("response"), dict) else {}
    scheme = "https" if entry.get("isTls") else "http"
    host = str(entry.get("host") or "")
    port = entry.get("port")
    default_port = 443 if scheme == "https" else 80
    hostport = host if port in (None, "", default_port) else "%s:%s" % (host, port)
    path = str(entry.get("path") or "/")
    query = entry.get("query")
    if isinstance(query, str) and query:
        path = "%s?%s" % (path, query)
    method = str(entry.get("method") or "?")
    status = resp.get("statusCode")
    url = "%s://%s%s" % (scheme, hostport, path)
    ts = _caido_ts(entry.get("createdAt")) or time.time()
    return {
        "key": "caido:%s" % entry.get("id"),
        "session_id": None,
        "ts": ts,
        "kind": em.KIND_WEB,
        "tool": "caido",
        "category": "web",
        "summary": em.one_line("%s %s -> %s" % (method, url, status if status is not None else "…")),
        "extra": {
            "id": entry.get("id"), "method": method, "url": url, "host": host,
            "path": path, "status": status, "roundtrip_ms": resp.get("roundtripTime"),
            "req_length": entry.get("length"), "resp_length": resp.get("length"),
            "tls": bool(entry.get("isTls")),
        },
    }
