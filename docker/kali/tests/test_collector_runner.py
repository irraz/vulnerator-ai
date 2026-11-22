"""Stdlib-only tests of the generic multi-tool runner (`collector_runner.py`).

They exercise the runner's LOGIC without the real binaries (prowler/scout/cloudsplaining):
  - los command builders producen el argv esperado por fuente;
  - los localizadores eligen el crudo correcto (JSON de ScoutSuite/Cloudsplaining, NUNCA
    el HTML);
  - finalization stages the raw as an artifact and builds `done` with the REFERENCE
    (sha256/size correctos); las fuentes no-Prowler NO populan el puente SSE;
  - Prowler sigue produciendo el mismo `done` que hoy (delegando en prowler_artifact);
  - ``run_collection`` orquesta end-to-end con un runner de subproceso simulado.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import artifact_store  # noqa: E402
import collector_runner  # noqa: E402
import tool_streaming  # noqa: E402


@pytest.fixture()
def staging(tmp_path, monkeypatch):
    monkeypatch.setenv("KALI_ARTIFACTS_DIR", str(tmp_path / "artifacts"))
    return tmp_path


# --------------------------------------------------------------- command builders


def test_scoutsuite_command_is_readonly_json_to_report_dir():
    cmd = collector_runner._scoutsuite_commands("123456789012", "/work", "/work/out", {})[0]
    assert cmd[0] == "scout" and cmd[1] == "aws"
    assert "--no-browser" in cmd
    assert cmd[cmd.index("--result-format") + 1] == "json"
    assert cmd[cmd.index("--report-dir") + 1] == "/work/out"


def test_cloudsplaining_commands_download_then_scan_json_output():
    cmds = collector_runner._cloudsplaining_commands("123456789012", "/work", "/work/out", {})
    assert len(cmds) == 2
    download, scan = cmds
    assert download[:2] == ["cloudsplaining", "download"]
    assert scan[:2] == ["cloudsplaining", "scan"]
    assert scan[scan.index("--output") + 1] == "/work/out"
    assert "--skip-open-report" in scan  # no abre navegador
    # ``download --output`` es un DIRECTORIO existente (no un fichero): cloudsplaining escribe
    # ``default.json`` dentro de workdir y el scan lee ese fichero.
    assert download[download.index("--output") + 1] == "/work"
    assert scan[scan.index("--input-file") + 1] == "/work/default.json"


def test_prowler_command_matches_mvp_shape(monkeypatch):
    monkeypatch.setenv("PROWLER_SERVICES", "iam s3")
    monkeypatch.setenv("PROWLER_REGIONS", "us-east-1")
    cmd = collector_runner._build_prowler_cmd("/out")
    assert cmd[1] == "aws"
    assert cmd[cmd.index("--output-directory") + 1] == "/out"
    assert "json-ocsf" in cmd
    assert cmd[cmd.index("--service") + 1] == "iam"
    assert cmd[cmd.index("--region") + 1] == "us-east-1"


# --------------------------------------------------------------- localizadores


def test_scoutsuite_locate_picks_results_js(tmp_path):
    outdir = tmp_path / "out"
    results = outdir / "scoutsuite-results"
    results.mkdir(parents=True)
    (results / "scoutsuite_results_aws-hermes.js").write_text("scoutsuite_results = {}", encoding="utf-8")
    (outdir / "report.html").write_text("<html></html>", encoding="utf-8")  # NO debe elegirse
    found = collector_runner._scoutsuite_locate(outdir)
    assert found is not None and found.suffix == ".js"


def test_cloudsplaining_locate_prefers_iam_results_over_findings_and_html(tmp_path):
    # Layout REAL del binario 0.9.1: escribe el HTML + ``iam-findings-*.json`` +
    # ``iam-results-*.json`` in ``outdir``. ``iam-findings-*.json`` is given the NEWEST mtime
    # so a naive "newest ``*.json``" locator would pick the
    # equivocado; el localizador debe fijar el prefijo y devolver el ``iam-results-*.json``.
    import os
    import time

    outdir = tmp_path / "out"
    outdir.mkdir()
    (outdir / "iam-report-default.html").write_text("<html></html>", encoding="utf-8")
    results = outdir / "iam-results-default.json"
    results.write_text("{}", encoding="utf-8")
    findings = outdir / "iam-findings-default.json"
    findings.write_text("{}", encoding="utf-8")
    newer = time.time() + 10
    os.utime(findings, (newer, newer))  # findings is the newest

    found = collector_runner._cloudsplaining_locate(outdir)
    assert found == results  # pinned por prefijo, no por mtime


def test_cloudsplaining_locate_falls_back_to_findings_never_html(tmp_path):
    # Sin ``iam-results-*.json`` (solo findings + HTML), cae al ``iam-findings-*.json`` y
    # NEVER the presentation HTML.
    outdir = tmp_path / "out"
    outdir.mkdir()
    (outdir / "iam-report-default.html").write_text("<html></html>", encoding="utf-8")
    findings = outdir / "iam-findings-default.json"
    findings.write_text("{}", encoding="utf-8")

    found = collector_runner._cloudsplaining_locate(outdir)
    assert found == findings


def test_locate_returns_none_when_no_output(tmp_path):
    outdir = tmp_path / "empty"
    outdir.mkdir()
    assert collector_runner._scoutsuite_locate(outdir) is None
    assert collector_runner._cloudsplaining_locate(outdir) is None


# --------------------------------------------------------------- finalize (no-bridge)


def test_finalize_scoutsuite_stages_artifact_and_done_ref_no_bridge(staging):
    outdir = staging / "out" / "scoutsuite-results"
    outdir.mkdir(parents=True)
    raw = b"scoutsuite_results =\n" + json.dumps({"services": {}}).encode("utf-8") + b";"
    (outdir / "scoutsuite_results_aws-hermes.js").write_bytes(raw)

    done = collector_runner.finalize(
        "scoutsuite", "exec-ss", staging / "out", 0, {"source": "scoutsuite"}
    )

    assert done["status"] == "done"
    assert "findings" not in done  # el control nunca lleva la carga
    artifact = done["artifact"]
    assert artifact["name"] == collector_runner.SCOUTSUITE_ARTIFACT_NAME
    assert artifact["size"] == len(raw)
    assert artifact["sha256"] == hashlib.sha256(raw).hexdigest()
    # The raw (``.js`` verbatim) was staged under the canonical name.
    staged = artifact_store.resolve("exec-ss", collector_runner.SCOUTSUITE_ARTIFACT_NAME)
    assert staged.read_bytes() == raw
    # D6: una fuente no-Prowler NO popula el puente SSE.
    assert tool_streaming.read_findings("exec-ss", 0)["findings"] == []


def test_finalize_cloudsplaining_stages_json_not_html(staging):
    outdir = staging / "out"
    outdir.mkdir(parents=True)
    (outdir / "iam-results-default.html").write_text("<html></html>", encoding="utf-8")
    raw = json.dumps({"customer_managed_policies": {}}).encode("utf-8")
    (outdir / "iam-results-default.json").write_bytes(raw)

    done = collector_runner.finalize(
        "cloudsplaining", "exec-cs", outdir, 0, {"source": "cloudsplaining"}
    )
    assert done["artifact"]["name"] == collector_runner.CLOUDSPLAINING_ARTIFACT_NAME
    assert done["artifact"]["sha256"] == hashlib.sha256(raw).hexdigest()
    staged = artifact_store.resolve("exec-cs", collector_runner.CLOUDSPLAINING_ARTIFACT_NAME)
    assert staged.read_bytes() == raw  # el JSON, no el HTML


def test_finalize_returns_none_when_no_output(staging):
    outdir = staging / "out"
    outdir.mkdir(parents=True)
    assert collector_runner.finalize("scoutsuite", "exec-x", outdir, 1, {"source": "scoutsuite"}) is None


# --------------------------------------------------------------- finalize prowler (bridge)


def test_finalize_prowler_matches_today_with_bridge(staging):
    outdir = staging / "out"
    outdir.mkdir(parents=True)
    findings = [{"check_id": f"c{i}", "severity": "high"} for i in range(3)]
    (outdir / "prowler-output.ocsf.json").write_bytes(json.dumps(findings).encode("utf-8"))

    done = collector_runner.finalize("prowler", "exec-pw", outdir, 0, {"source": "prowler"})

    assert done["status"] == "done"
    assert done["findings_count"] == 3
    assert done["artifact"]["name"] == collector_runner.PROWLER_ARTIFACT_NAME
    assert "findings" not in done  # findings por referencia, no inline
    # Prowler DOES keep the compat SSE bridge.
    page = tool_streaming.read_findings("exec-pw", 0)
    assert [f["check_id"] for f in page["findings"]] == ["c0", "c1", "c2"]


# --------------------------------------------------------------- disponibilidad


def test_available_collectors_reports_bool_per_source():
    avail = collector_runner.available_collectors()
    assert set(avail) == {"prowler", "scoutsuite", "cloudsplaining"}
    assert all(isinstance(v, bool) for v in avail.values())


# --------------------------------------------------------------- run_collection e2e


def _fake_runner(write_output):
    """Fake of ``run_tool_streaming``: writes fixture output and returns success."""

    def _run(cmd, execution_id, timeout=0, env=None, cwd=None):
        write_output(cmd)
        return (0, False, False)

    return _run


def test_run_collection_scoutsuite_e2e(staging, monkeypatch):
    monkeypatch.setattr(collector_runner.shutil, "which", lambda b: f"/usr/bin/{b}")
    raw = b"scoutsuite_results = " + json.dumps({"services": {}}).encode("utf-8") + b";"

    def _write(cmd):
        outdir = Path(cmd[cmd.index("--report-dir") + 1]) / "scoutsuite-results"
        outdir.mkdir(parents=True, exist_ok=True)
        (outdir / "scoutsuite_results_aws-hermes.js").write_bytes(raw)

    monkeypatch.setattr(
        collector_runner.tool_streaming, "run_tool_streaming", _fake_runner(_write)
    )

    done = collector_runner.run_collection("scoutsuite", "123456789012", "exec-run-ss")
    assert done["status"] == "done"
    assert done["artifact"]["name"] == collector_runner.SCOUTSUITE_ARTIFACT_NAME
    assert done["artifact"]["sha256"] == hashlib.sha256(raw).hexdigest()
    assert tool_streaming.read_findings("exec-run-ss", 0)["findings"] == []  # sin puente


def test_run_collection_cloudsplaining_e2e(staging, monkeypatch):
    monkeypatch.setattr(collector_runner.shutil, "which", lambda b: f"/usr/bin/{b}")
    raw = json.dumps({"customer_managed_policies": {}}).encode("utf-8")

    def _write(cmd):
        if cmd[1] == "download":
            # ``download --output`` es un DIRECTORIO existente; cloudsplaining escribe
            # ``default.json`` dentro (como el binario real), no en la ruta tal cual.
            Path(cmd[cmd.index("--output") + 1], "default.json").write_text(
                "{}", encoding="utf-8"
            )
        elif cmd[1] == "scan":
            # El scan exige que su ``--input-file`` (el default.json del paso 1) exista.
            assert Path(cmd[cmd.index("--input-file") + 1]).is_file()
            outdir = Path(cmd[cmd.index("--output") + 1])
            outdir.mkdir(parents=True, exist_ok=True)
            # Real binary layout (0.9.1): presentation HTML + the two scan JSONs.
            (outdir / "iam-report-default.html").write_text("<html></html>", encoding="utf-8")
            (outdir / "iam-findings-default.json").write_bytes(raw)
            (outdir / "iam-results-default.json").write_bytes(raw)

    monkeypatch.setattr(
        collector_runner.tool_streaming, "run_tool_streaming", _fake_runner(_write)
    )

    done = collector_runner.run_collection("cloudsplaining", "123456789012", "exec-run-cs")
    assert done["status"] == "done"
    assert done["artifact"]["name"] == collector_runner.CLOUDSPLAINING_ARTIFACT_NAME
    assert done["artifact"]["sha256"] == hashlib.sha256(raw).hexdigest()


def test_run_collection_missing_binary_fails_honestly(monkeypatch):
    monkeypatch.setattr(collector_runner.shutil, "which", lambda b: None)
    with pytest.raises(RuntimeError) as exc:
        collector_runner.run_collection("scoutsuite", "1", "exec-nobinary")
    assert "is not available" in str(exc.value)


def test_run_collection_unknown_source_raises():
    with pytest.raises(RuntimeError):
        collector_runner.run_collection("nessus", "1", "exec-unknown")
