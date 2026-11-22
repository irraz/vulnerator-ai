"""Stdlib-only tests of scan finalization (`docker/kali/prowler_artifact.py`).

Ejercitan el camino post-escaneo del worker SIN `mcp`/`prowler`: con un OCSF de
fixture, el `done` trae la REFERENCIA `artifact` (sha256/size correctos) y NO los
inline findings; the `read_scan_findings` bridge (via tool_streaming) keeps serving
pages; unreadable output yields `None` (the caller publishes failed).
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

# Modules under test in docker/kali/ (pure stdlib; no `mcp`/`anyio` import).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import artifact_store  # noqa: E402
import prowler_artifact  # noqa: E402
import tool_streaming  # noqa: E402


def _ocsf(n: int) -> list[dict]:
    return [{"check_id": f"c{i}", "severity": "high"} for i in range(n)]


@pytest.fixture()
def staging(tmp_path, monkeypatch):
    monkeypatch.setenv("KALI_ARTIFACTS_DIR", str(tmp_path / "artifacts"))
    return tmp_path


def _write_ocsf(outdir: Path, findings: list[dict]) -> bytes:
    outdir.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(findings).encode("utf-8")
    (outdir / "prowler-output.ocsf.json").write_bytes(raw)
    return raw


# --------------------------------------------------------- done con artifact ref


def test_finalize_scan_stages_artifact_and_done_has_ref_not_inline(staging):
    outdir = staging / "scan-out"
    raw = _write_ocsf(outdir, _ocsf(5))

    done = prowler_artifact.finalize_scan("exec-1", outdir, 0, {"account_id": "123456789012"})

    assert done["status"] == "done"
    assert done["findings_count"] == 5
    # Clave de la oleada: NADA de findings inline en el canal de control.
    assert "findings" not in done
    # The small data-plane reference, with sha256/size of the RAW output.
    artifact = done["artifact"]
    assert artifact["execution_id"] == "exec-1"
    assert artifact["name"] == prowler_artifact.PROWLER_ARTIFACT_NAME
    assert artifact["size"] == len(raw)
    assert artifact["sha256"] == hashlib.sha256(raw).hexdigest()

    # The raw artifact was staged identically (HTTP will serve it to the client).
    staged = artifact_store.resolve("exec-1", prowler_artifact.PROWLER_ARTIFACT_NAME)
    assert staged.read_bytes() == raw


def test_finalize_scan_keeps_read_scan_findings_bridge(staging):
    """Puente intacto: los findings quedan paginables por tool_streaming."""
    outdir = staging / "scan-out"
    _write_ocsf(outdir, _ocsf(3))

    prowler_artifact.finalize_scan("exec-2", outdir, 0, {})

    page = tool_streaming.read_findings("exec-2", 0)
    assert [f["check_id"] for f in page["findings"]] == ["c0", "c1", "c2"]
    assert page["done"] is True


def test_finalize_scan_unreadable_output_returns_none(staging):
    """No readable JSON output -> None (the worker publishes failed with a diagnostic)."""
    outdir = staging / "empty"
    outdir.mkdir(parents=True, exist_ok=True)
    assert prowler_artifact.finalize_scan("exec-3", outdir, 1, {}) is None


# ---------------------------------------------------------- read_prowler_output


def test_read_prowler_output_picks_readable_file(staging):
    outdir = staging / "out"
    raw = _write_ocsf(outdir, _ocsf(2))
    path, findings = prowler_artifact.read_prowler_output(outdir)
    assert path is not None
    assert path.read_bytes() == raw
    assert len(findings) == 2


def test_read_prowler_output_wraps_dict_payload(staging):
    outdir = staging / "out"
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "r.json").write_text(json.dumps({"findings": _ocsf(4)}), encoding="utf-8")
    _path, findings = prowler_artifact.read_prowler_output(outdir)
    assert len(findings) == 4


def test_finalize_scan_bridge_survives_staging_failure(staging, monkeypatch):
    """Si el staging falla, se publica done SIN artifact ref pero el puente sigue.

    Es la red de seguridad: el plano de datos nunca tumba el escaneo; se cae al
    puente read_scan_findings.
    """
    outdir = staging / "out"
    _write_ocsf(outdir, _ocsf(2))

    def _boom(*_a, **_k):
        raise OSError("disk full")

    monkeypatch.setattr(artifact_store, "put_file", _boom)

    done = prowler_artifact.finalize_scan("exec-9", outdir, 0, {})
    assert done["status"] == "done"
    assert "artifact" not in done
    # Puente intacto pese al fallo de staging.
    assert tool_streaming.read_findings("exec-9", 0)["findings"]
