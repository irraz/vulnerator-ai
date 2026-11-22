"""Tests stdlib-only del generador de informe de pentest (`docker/kali/report_gen.py`).

They do not import `mcp`/`anyio`: only standard library + pytest. They verify:
  - ``render_markdown`` produce las secciones esperadas y agrupa por estado;
  - CVSS/CWE appear only in confirmed findings;
  - evidence (command/output) is rendered verbatim in code blocks;
  - el resumen ejecutivo refleja "sin confirmados" cuando no los hay (no dice "seguro");
  - ``generate`` lee del store y stagea el Markdown como artefacto descargable;
  - ``main`` writes the readable line and returns 0.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import artifact_store  # noqa: E402
import finding_store  # noqa: E402
import report_gen  # noqa: E402


@pytest.fixture()
def staging(tmp_path, monkeypatch):
    monkeypatch.setenv("KALI_ARTIFACTS_DIR", str(tmp_path))
    return tmp_path


# ------------------------------------------------------------------ render_markdown


def test_render_has_core_sections():
    md = report_gen.render_markdown("eng-x", [], generated_at="2026-01-01T00:00:00Z")
    assert "# Pentest report" in md
    assert "## Executive summary" in md
    assert "## Summary by status" in md
    assert "## Methodology" in md
    assert "## Findings" in md
    assert "## Scope and limitations" in md


def test_render_empty_does_not_claim_secure():
    md = report_gen.render_markdown("eng-x", [])
    assert "No exploitable finding was confirmed" in md
    assert "secure" in md  # aparece precisamente para NEGAR ese veredicto ("secure system")


def test_render_groups_and_counts_by_state():
    findings = [
        {"title": "a", "state": "confirmed"},
        {"title": "b", "state": "confirmed"},
        {"title": "c", "state": "hypothesis"},
        {"title": "d", "state": "partial"},
        {"title": "e", "state": "discarded"},
    ]
    md = report_gen.render_markdown("eng-x", findings)
    assert "| Confirmed | 2 |" in md
    assert "| Partial | 1 |" in md
    assert "| Hypothesis | 1 |" in md
    assert "| Discarded | 1 |" in md
    # Confirmed findings render before hypotheses.
    assert md.index("Confirmed (2)") < md.index("Hypothesis (1)")


def test_render_cvss_only_for_confirmed():
    confirmed = report_gen.render_markdown(
        "e", [{"title": "x", "state": "confirmed", "cvss": "9.8", "cwe": "CWE-89"}]
    )
    assert "CVSS 3.1" in confirmed
    assert "9.8" in confirmed
    assert "CWE-89" in confirmed

    hypo = report_gen.render_markdown("e", [{"title": "x", "state": "hypothesis", "cvss": "9.8"}])
    assert "CVSS 3.1" not in hypo  # unconfirmed items are not scored


def test_render_evidence_verbatim_in_fence():
    finding = {
        "title": "RCE en /ping",
        "state": "confirmed",
        "evidence": {
            "command": "curl 'http://t/ping?ip=;id'",
            "returncode": 0,
            "output": "uid=0(root) gid=0(root)",
        },
    }
    md = report_gen.render_markdown("e", [finding])
    assert "curl 'http://t/ping?ip=;id'" in md
    assert "uid=0(root)" in md
    assert "````" in md  # 4-backtick code block


def test_render_change_block_has_tag_and_revert():
    finding = {
        "title": "Backdoor user creado",
        "state": "confirmed",
        "change": {"tag": "vulnerator-ai", "revert": "aws iam delete-user --user-name bd"},
    }
    md = report_gen.render_markdown("e", [finding])
    assert "vulnerator-ai" in md
    assert "aws iam delete-user --user-name bd" in md


# ------------------------------------------------------------------ generate / main


def test_generate_reads_store_and_stages_markdown(staging):
    finding_store.append("eng-gen", {
        "title": "SSH abierto",
        "state": "confirmed",
        "evidence": {"command": "nmap -p22 -sV 10.0.0.5", "output": "22/tcp open ssh OpenSSH 8.9p1", "returncode": 0},
    })
    finding_store.append("eng-gen", {"title": "maybe SQLi", "state": "hypothesis"})

    result = report_gen.generate("eng-gen")
    assert result["status"] == "done"
    assert result["findings_count"] == 2
    assert result["artifact"]["name"] == report_gen.REPORT_NAME

    # The Markdown was staged and is downloadable; it contains the titles.
    staged = artifact_store.resolve("eng-gen", report_gen.REPORT_NAME)
    text = staged.read_text(encoding="utf-8")
    assert "SSH abierto" in text
    assert "maybe SQLi" in text


def test_main_prints_line_and_returns_zero(staging, capsys):
    finding_store.append("eng-main", {
        "title": "hallazgo",
        "state": "confirmed",
        "evidence": {"command": "curl -sS http://t/x", "output": "HTTP 200 body con prueba del hallazgo", "returncode": 0},
    })
    rc = report_gen.main(["--engagement", "eng-main"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "report generated: eng-main/pentest-report.md" in out
    assert "1 findings" in out
