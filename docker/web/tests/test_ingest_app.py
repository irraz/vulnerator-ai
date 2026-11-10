"""Tests del ingestor (Hermes falso, sin red) y de la app HTTP (auth, API, descargas)."""

from __future__ import annotations

import asyncio
import base64
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import ingest  # noqa: E402
import web_app  # noqa: E402
from fixtures import synthetic_session as fx  # noqa: E402
from trace_store import TraceStore  # noqa: E402


class FakeHermes:
    """Imita ``HermesSessions`` sobre la fixture: expone los mensajes poco a poco."""

    def __init__(self, upto: int) -> None:
        self.upto = upto
        self.calls: list[tuple] = []

    async def health(self):
        return {"version": "0.23.0"}

    async def list_sessions(self, limit=50):
        return [fx.session_meta(message_count=self.upto)]

    async def messages(self, sid, *, order, offset=0, limit=500):
        self.calls.append((order, offset, limit))
        msgs = fx.messages()[: self.upto]
        if order == "latest":
            return list(reversed(msgs))[:limit]
        return msgs[offset: offset + limit]


def test_session_ingestor_incremental_and_poc_recording(tmp_path):
    async def go():
        st = TraceStore()
        hermes = FakeHermes(upto=6)
        ing = ingest.SessionIngestor(st, ingest.Notifier(), hermes, poc_dir=str(tmp_path))
        first = await ing.poll_once()
        assert first > 0 and hermes.calls[0][0] == "oldest"
        hermes.upto = len(fx.messages())
        second = await ing.poll_once()
        assert second > 0 and hermes.calls[-1][0] == "latest"
        assert await ing.poll_once() == 0  # sesión "activa": re-sync idempotente, 0 nuevos
        return st

    asyncio.run(go())
    files = sorted(p.name for p in tmp_path.rglob("*") if p.is_file())
    assert len(files) == 2  # solo el PoC CONFIRMADO y ACEPTADO se graba (.cast + .md)
    assert any(f.endswith(".cast") for f in files) and any(f.endswith(".md") for f in files)
    assert all("Boolean-SQL-injection" in f for f in files)


def test_notifier_wakes_waiters():
    async def go():
        n = ingest.Notifier()
        waiter = asyncio.create_task(n.wait(0, 5))
        await asyncio.sleep(0.01)
        await n.notify_async()
        assert await asyncio.wait_for(waiter, 1) == 1
        assert await n.wait(1, 0.01) == 1  # timeout sin cambios

    asyncio.run(go())


def test_select_ready_entries_waits_for_response():
    entries = fx.caido_entries()
    now = fx.T0 + 20
    assert [e["id"] for e in ingest.select_ready_entries(entries, now)] == ["12"]
    later = fx.T0 + 19 + ingest.CAIDO_PENDING_GRACE_S + 1
    assert [e["id"] for e in ingest.select_ready_entries(entries, later)] == ["12", "13"]


def test_caido_feed_reports_failure_without_faking():
    async def go():
        st = TraceStore()
        feed = ingest.CaidoFeed(st, ingest.Notifier(),
                                lambda q, n: {"status": "unreachable", "error": "refused"})
        assert await feed.poll_once() == 0
        assert feed.status["ok"] is False and "unreachable" in feed.status["last_error"]
        ok = ingest.CaidoFeed(st, ingest.Notifier(),
                              lambda q, n: {"status": "done", "count": 2,
                                            "entries": fx.caido_entries()})
        assert await ok.poll_once() == 1

    asyncio.run(go())


def test_poc_basename_is_path_safe():
    poc = {"finding": {"title": "../../etc/passwd <x>"}, "call_id": "a/b"}
    name = ingest.poc_basename(poc)
    assert "/" not in name and "\\" not in name and "<" not in name
    assert not name.startswith(".")


def test_poc_files_never_escape_poc_dir(tmp_path):
    from fixtures import synthetic_session as _fx
    import poc_replay
    st = TraceStore()
    st.ingest_messages(_fx.SID, _fx.messages())
    poc = poc_replay.build_pocs(st.session_events(_fx.SID))[0]
    root = tmp_path / "pocs"
    for evil in ("..", "../..", "/etc", ".", ""):
        poc["session_id"] = evil
        base = ingest.write_poc_files(root, poc)
        assert root.resolve() in base.resolve().parents


# --------------------------------------------------------------------------- app
def _settings():
    s = web_app.Settings()
    s.password = "s3cret-test"
    s.user = "admin"
    s.hermes_key = "k" * 16
    s.db_path = ":memory:"
    s.poc_dir = ""
    s.background = False
    s.dashboard_internal = ""
    s.webapp_internal = ""
    return s


def _auth(user="admin", pw="s3cret-test"):
    return {"Authorization": "Basic " + base64.b64encode(("%s:%s" % (user, pw)).encode()).decode()}


@pytest.fixture()
def client():
    from starlette.testclient import TestClient
    app = web_app.create_app(_settings())
    with TestClient(app) as c:
        st = app.state.store
        st.upsert_session(fx.session_meta())
        st.ingest_messages(fx.SID, fx.messages())
        st.ingest_web(fx.caido_entries())
        yield c


def test_auth_required_and_healthz_open(client):
    assert client.get("/healthz").status_code == 200
    r = client.get("/api/sessions")
    assert r.status_code == 401 and "Basic" in r.headers["www-authenticate"]
    assert client.get("/api/sessions", headers=_auth(pw="wrong")).status_code == 401
    assert client.get("/api/sessions", headers=_auth(user="root")).status_code == 401
    assert client.get("/api/sessions", headers={"Authorization": "Basic !!!"}).status_code == 401
    assert client.get("/api/sessions", headers=_auth()).status_code == 200


def test_security_headers(client):
    r = client.get("/api/status", headers=_auth())
    csp = r.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "unsafe-inline" not in csp
    assert r.headers["x-content-type-options"] == "nosniff"
    assert client.get("/api/status").headers["x-frame-options"] == "DENY"  # también en 401


def test_sessions_events_trace_api(client):
    rows = client.get("/api/sessions", headers=_auth()).json()["data"]
    assert rows[0]["id"] == fx.SID
    evs = client.get("/api/sessions/%s/events?tail=5" % fx.SID, headers=_auth()).json()["data"]
    assert len(evs) == 5
    calls = client.get("/api/sessions/%s/events?kinds=tool.call" % fx.SID,
                       headers=_auth()).json()["data"]
    assert len(calls) == 6
    trace = client.get("/api/sessions/%s/trace" % fx.SID, headers=_auth()).json()
    assert trace["summary"]["spans"] == 6 and len(trace["spans"]) == 6
    assert client.get("/api/sessions/..%2Fetc/trace", headers=_auth()).status_code in (400, 404)


def test_pocs_api_and_downloads(client):
    pocs = client.get("/api/sessions/%s/pocs" % fx.SID, headers=_auth()).json()["data"]
    assert len(pocs) == 2 and pocs[0]["confirmed"] is True
    index = client.get("/api/pocs", headers=_auth()).json()["data"]
    assert {p["store_status"] for p in index} == {"recorded", "rejected"}
    cast = client.get("/api/sessions/%s/pocs/call_find.cast" % fx.SID, headers=_auth())
    assert cast.status_code == 200 and "attachment" in cast.headers["content-disposition"]
    assert json.loads(cast.text.splitlines()[0])["version"] == 2
    md = client.get("/api/sessions/%s/pocs/call_find.md" % fx.SID, headers=_auth())
    assert md.status_code == 200 and "## Reproducción" in md.text
    assert client.get("/api/sessions/%s/pocs/call_find.exe" % fx.SID,
                      headers=_auth()).status_code == 400
    assert client.get("/api/sessions/%s/pocs/nope.md" % fx.SID, headers=_auth()).status_code == 404


def test_event_detail_and_web(client):
    calls = client.get("/api/sessions/%s/events?kinds=tool.result" % fx.SID,
                       headers=_auth()).json()["data"]
    detail = client.get("/api/events/%d" % calls[0]["seq"], headers=_auth()).json()
    assert detail["output"].startswith("80/tcp open")
    web = client.get("/api/web?tail=10", headers=_auth()).json()["data"]
    assert [w["extra"]["method"] for w in web] == ["GET", "POST"]


def test_index_served(client):
    r = client.get("/", headers=_auth())
    assert r.status_code == 200 and "text/html" in r.headers["content-type"]


def test_settings_fail_closed():
    s = web_app.Settings()
    s.password = ""
    s.hermes_key = ""
    assert len(s.validate()) == 2


def test_status_reports_hermes_ui_probe_without_faking(client):
    st = client.get("/api/status", headers=_auth()).json()
    for key in ("dashboard", "webapp"):
        assert st["hermes"][key]["up"] is False
        assert st["hermes"][key]["detail"] == "sin URL interna configurada"
    assert st["hermes"]["dashboard"]["port"] == "9119"


# --------------------------------------------------------------------------- sesión
def _key():
    s = _settings()
    return web_app.session_key(s.user, s.password, s.hermes_key)


def test_browser_without_session_is_redirected_to_login_api_gets_401(client):
    r = client.get("/", headers={"Accept": "text/html"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/login?next=/")
    assert client.get("/api/status", follow_redirects=False).status_code == 401
    assert client.get("/login").status_code == 200
    assert client.get("/static/login.js").status_code == 200


def test_login_form_sets_session_cookie(client):
    bad = client.post("/login", content="user=admin&password=nope&next=/",
                      headers={"Content-Type": "application/x-www-form-urlencoded"}, follow_redirects=False)
    assert bad.status_code == 303 and "error=1" in bad.headers["location"]
    assert web_app.SESSION_COOKIE not in bad.cookies
    ok = client.post("/login", content="user=admin&password=s3cret-test&next=/%23traces",
                     headers={"Content-Type": "application/x-www-form-urlencoded"}, follow_redirects=False)
    assert ok.status_code == 303 and ok.headers["location"] == "/#traces"
    assert "httponly" in ok.headers["set-cookie"].lower() and "samesite=strict" in ok.headers["set-cookie"].lower()
    assert client.get("/api/status").status_code == 200  # la cookie basta, sin Basic
    client.get("/logout", follow_redirects=False)
    assert client.get("/api/status").status_code == 401


def test_login_rejects_open_redirect(client):
    for evil in ("//evil.example.com/", "https://evil.example.com/", "/\\evil.example.com"):
        r = client.post("/login", content="user=admin&password=s3cret-test&next=" + evil,
                        headers={"Content-Type": "application/x-www-form-urlencoded"}, follow_redirects=False)
        assert r.headers["location"] == "/"


def test_session_cookie_signature_and_expiry():
    key = _key()
    good = web_app.make_session_cookie(key, "admin")
    assert web_app.check_session_cookie(key, good)
    assert not web_app.check_session_cookie(b"x", good)
    assert not web_app.check_session_cookie(key, web_app.make_session_cookie(key, "admin", now=1_000.0))
    assert not web_app.check_session_cookie(key, "garbage")
    body, mac = good.split(".")
    tampered = web_app._b64(web_app._unb64(body).replace(b"admin", b"root!")) + "." + mac
    assert not web_app.check_session_cookie(key, tampered)
