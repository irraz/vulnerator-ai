"""Tests stdlib-only del staging de artefactos de kali (`docker/kali/artifact_store.py`).

They do not import `mcp`/`anyio`: only standard library + pytest. Verify put (bytes/
fichero) con sha256/size correctos, lectura de meta, confinamiento de rutas
(traversal/absoluta rechazadas) y tolerancia a ids/nombres desconocidos.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

# The module under test lives in docker/kali/ (alongside the MCP server, which is NOT
# imported here because it pulls in `mcp`/`anyio`). We add it to the path explicitly.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import artifact_store  # noqa: E402


@pytest.fixture()
def staging(tmp_path, monkeypatch):
    """Points the staging root to a tmp dir per test (env read at call time)."""
    monkeypatch.setenv("KALI_ARTIFACTS_DIR", str(tmp_path))
    return tmp_path


# ------------------------------------------------------------------ put_bytes


def test_put_bytes_stages_file_with_sha256_and_size(staging):
    data = b'{"findings": [1,2,3]}'
    entry = artifact_store.put_bytes("exec-1", "prowler.ocsf.json", data, {"tool": "prowler"})

    assert entry["size"] == len(data)
    assert entry["sha256"] == hashlib.sha256(data).hexdigest()
    assert entry["name"] == "prowler.ocsf.json"
    assert entry["meta"]["tool"] == "prowler"

    # The file was staged with verbatim content.
    staged = artifact_store.resolve("exec-1", "prowler.ocsf.json")
    assert staged.read_bytes() == data


# ------------------------------------------------------------------- put_file


def test_put_file_copies_source_with_correct_digest(staging, tmp_path):
    src = tmp_path / "src.json"
    payload = b'{"ocsf": true}' * 100
    src.write_bytes(payload)

    entry = artifact_store.put_file(
        "exec-2", "prowler.ocsf.json", src, {"tool": "prowler", "phase": "collection"}
    )

    assert entry["size"] == len(payload)
    assert entry["sha256"] == hashlib.sha256(payload).hexdigest()
    staged = artifact_store.resolve("exec-2", "prowler.ocsf.json")
    assert staged.read_bytes() == payload


def test_put_file_survives_source_cleanup(staging, tmp_path):
    """The staged artifact survives even if the source file is deleted afterwards.

    Es el caso real: Prowler escribe en un TemporaryDirectory que se limpia al salir
    del worker; el staging debe tener ya una COPIA independiente.
    """
    src = tmp_path / "ephemeral.json"
    src.write_bytes(b"ephemeral")
    artifact_store.put_file("exec-3", "out.json", src)
    src.unlink()

    staged = artifact_store.resolve("exec-3", "out.json")
    assert staged.read_bytes() == b"ephemeral"


# ----------------------------------------------------------------- read_meta


def test_read_meta_returns_index_of_staged_artifacts(staging):
    artifact_store.put_bytes("exec-4", "a.json", b"aaa", {"tool": "prowler"})
    artifact_store.put_bytes("exec-4", "b.json", b"bb", {"tool": "nmap"})

    index = artifact_store.read_meta("exec-4")
    assert index["execution_id"] == "exec-4"
    assert set(index["artifacts"]) == {"a.json", "b.json"}
    assert index["artifacts"]["a.json"]["size"] == 3


def test_stat_returns_entry_or_none(staging):
    artifact_store.put_bytes("exec-5", "only.json", b"data")
    entry = artifact_store.stat("exec-5", "only.json")
    assert entry is not None
    assert entry["sha256"] == hashlib.sha256(b"data").hexdigest()

    # Nombre desconocido -> None (no revienta).
    assert artifact_store.stat("exec-5", "missing.json") is None


# --------------------------------------------------- unknown ids no revientan


def test_read_meta_unknown_execution_is_empty(staging):
    assert artifact_store.read_meta("never") == {}


def test_stat_unknown_execution_is_none(staging):
    assert artifact_store.stat("never", "whatever.json") is None


# ------------------------------------------------------------- confinamiento


@pytest.mark.parametrize(
    "execution_id,name",
    [
        ("exec-1", "../escape.json"),
        ("../../etc", "passwd"),
        ("exec-1", "/etc/passwd"),
        ("exec-1", "a/b.json"),
        ("exec-1", ".."),
        ("", "x.json"),
    ],
)
def test_resolve_rejects_traversal_and_separators(staging, execution_id, name):
    with pytest.raises(ValueError):
        artifact_store.resolve(execution_id, name)


def test_resolve_confines_under_root(staging):
    """A valid name resolves under the staging root."""
    path = artifact_store.resolve("exec-1", "prowler.ocsf.json")
    assert str(path).startswith(str(Path(staging).resolve()))
