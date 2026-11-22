"""Tests stdlib-only del servidor HTTP de artefactos (`docker/kali/artifact_http.py`).

Starts the server on an ephemeral port in a thread and exercises it with `urllib.request`
(stdlib). Verifies: GET with token -> 200 + identical bytes (incl. a blob > 1 MiB via
el stream chunked), 403 sin token, 400 ante traversal, 404 si no existe, y fail-closed
si se intenta arrancar sin token.
"""

from __future__ import annotations

import hashlib
import sys
import urllib.error
import urllib.request
from pathlib import Path

import pytest

# The modules under test live in docker/kali/ (they do not import `mcp`/`anyio`).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import artifact_http  # noqa: E402
import artifact_store  # noqa: E402

_TOKEN = "test-shared-token"


@pytest.fixture()
def server(tmp_path, monkeypatch):
    """Staging in tmp + HTTP server on ephemeral port; closed on completion."""
    monkeypatch.setenv("KALI_ARTIFACTS_DIR", str(tmp_path))
    srv, _thread = artifact_http.serve_in_thread("127.0.0.1", 0, _TOKEN)
    yield srv
    srv.shutdown()


def _base_url(srv) -> str:
    host, port = srv.server_address
    return f"http://{host}:{port}"


def _get(url: str, token: str | None = _TOKEN) -> tuple[int, bytes, dict]:
    headers = {}
    if token is not None:
        headers["X-Artifact-Token"] = token
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), dict(exc.headers)


# ------------------------------------------------------------------- 200 OK


def test_get_with_token_returns_bytes(server):
    data = b'{"findings": [1, 2, 3]}'
    artifact_store.put_bytes("exec-1", "prowler.ocsf.json", data, {"tool": "prowler"})

    status, body, headers = _get(f"{_base_url(server)}/artifacts/exec-1/prowler.ocsf.json")

    assert status == 200
    assert body == data
    assert int(headers["Content-Length"]) == len(data)
    assert headers["X-Artifact-Sha256"] == hashlib.sha256(data).hexdigest()


def test_get_large_blob_over_1mib_streams_chunked(server):
    """A blob > 1 MiB is served via chunked stream, byte-for-byte identical.

    This is exactly what the single SSE event (1,048,576 B cap) could not deliver.
    """
    size = 3 * 1024 * 1024  # 3 MiB, muy por encima del viejo tope SSE
    payload = (b"B" * size)
    artifact_store.put_bytes("exec-big", "big.json", payload, {"tool": "prowler"})

    status, body, headers = _get(f"{_base_url(server)}/artifacts/exec-big/big.json")

    assert status == 200
    assert len(body) == size
    assert hashlib.sha256(body).hexdigest() == hashlib.sha256(payload).hexdigest()
    assert headers["X-Artifact-Sha256"] == hashlib.sha256(payload).hexdigest()


# --------------------------------------------------------------------- 403


def test_get_without_token_is_forbidden(server):
    artifact_store.put_bytes("exec-1", "a.json", b"x")
    status, _body, _headers = _get(f"{_base_url(server)}/artifacts/exec-1/a.json", token=None)
    assert status == 403


def test_get_with_wrong_token_is_forbidden(server):
    artifact_store.put_bytes("exec-1", "a.json", b"x")
    status, _body, _headers = _get(
        f"{_base_url(server)}/artifacts/exec-1/a.json", token="nope"
    )
    assert status == 403


# --------------------------------------------------------------------- 400


def test_get_traversal_path_is_bad_request(server):
    # `%2e%2e` -> `..` tras unquote: el confinamiento de resolve lo rechaza (400).
    status, _body, _headers = _get(f"{_base_url(server)}/artifacts/exec-1/%2e%2e%2fsecret")
    assert status == 400


def test_get_multisegment_name_is_bad_request(server):
    status, _body, _headers = _get(f"{_base_url(server)}/artifacts/exec-1/a/b.json")
    assert status == 400


# --------------------------------------------------------------------- 404


def test_get_missing_artifact_is_not_found(server):
    status, _body, _headers = _get(f"{_base_url(server)}/artifacts/exec-1/missing.json")
    assert status == 404


def test_get_non_artifact_path_is_not_found(server):
    status, _body, _headers = _get(f"{_base_url(server)}/health")
    assert status == 404


# ----------------------------------------------------------- fail-closed


def test_make_server_requires_token():
    with pytest.raises(ValueError):
        artifact_http.make_server("127.0.0.1", 0, "")
