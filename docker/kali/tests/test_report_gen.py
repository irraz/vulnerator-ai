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

import hashlib
import json
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


# ------------------------------------------------------------------ render_html / determinism

_EXAMPLE_FINDINGS_PATH = Path(__file__).resolve().parents[3] / "docs" / "example-findings.jsonl"
_FIXED_TIME = "2026-11-23T00:00:00Z"


def _example_findings() -> list[dict]:
    """Synthetic engagement built from the documented findings-store sample."""
    lines = _EXAMPLE_FINDINGS_PATH.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def test_render_html_is_byte_deterministic():
    findings = _example_findings()
    first = report_gen.render_html("eng-det", findings, generated_at=_FIXED_TIME)
    second = report_gen.render_html("eng-det", findings, generated_at=_FIXED_TIME)
    assert first == second
    assert hashlib.sha256(first.encode("utf-8")).hexdigest() == hashlib.sha256(
        second.encode("utf-8")
    ).hexdigest()


def test_render_html_has_all_required_sections():
    document = report_gen.render_html("eng-x", _example_findings(), generated_at=_FIXED_TIME)
    assert document.lstrip().lower().startswith("<!doctype html>")
    for needle in (
        "<header",
        'class="report-meta"',
        'class="cvss-hero"',
        "01 /",
        "Executive Summary",
        "02 /",
        "Main Finding",
        "03 /",
        "Exploitability Evidence",
        "04 /",
        "Evaluated &amp; Discarded Vectors",
        "05 /",
        "Remediation",
        "06 /",
        "Scope Compliance",
        "<footer",
    ):
        assert needle in document, needle


def test_render_html_empty_store_keeps_sections_without_secure_claim():
    document = report_gen.render_html("eng-empty", [], generated_at=_FIXED_TIME)
    assert 'class="cvss-hero"' in document
    assert "No exploitable finding was confirmed" in document
    assert "secure system" in document  # only to deny that verdict


def test_render_html_escapes_untrusted_evidence():
    finding = {
        "title": "<script>alert('title')</script>",
        "state": "confirmed",
        "evidence": {
            "command": "echo '<img src=x onerror=alert(1)>'",
            "output": "<script>alert('output')</script>",
            "returncode": 0,
        },
    }
    document = report_gen.render_html("eng-esc", [finding], generated_at=_FIXED_TIME)
    assert "&lt;script&gt;" in document
    assert "<script>alert" not in document


def test_render_html_evaluated_and_discarded_rows():
    findings = [
        {"title": "discarded vector", "state": "discarded"},
        {"title": "open hypothesis", "state": "hypothesis"},
    ]
    document = report_gen.render_html("eng-vectors", findings, generated_at=_FIXED_TIME)
    assert 'class="discarded-row"' in document
    assert "discarded vector" in document
    assert "open hypothesis" in document


# ------------------------------------------------------------------ staged artifact names


def _append_example_finding(engagement_id: str) -> None:
    finding_store.append(
        engagement_id,
        {
            "title": "Reproducible finding",
            "state": "confirmed",
            "phase": "observe",
            "evidence": {
                "command": "curl -sS http://192.0.2.1/",
                "output": "HTTP/1.1 200 OK Server: lighttpd/1.4.39",
                "returncode": 0,
            },
            "remediation": "Patch the service.",
        },
    )
    finding_store.append(engagement_id, {"title": "Discarded vector", "state": "discarded"})


def test_generate_html_stages_stable_name(staging):
    _append_example_finding("eng-html")
    result = report_gen.generate("eng-html", fmt="html", generated_at=_FIXED_TIME)
    assert report_gen.REPORT_HTML_NAME == "pentest-report.html"
    assert result["artifact"]["name"] == report_gen.REPORT_HTML_NAME
    staged = artifact_store.resolve("eng-html", report_gen.REPORT_HTML_NAME)
    assert staged.read_text(encoding="utf-8").startswith("<!doctype html>")
    assert not artifact_store.resolve("eng-html", report_gen.REPORT_NAME).exists()


def test_generate_both_stages_md_then_html(staging):
    _append_example_finding("eng-both")
    result = report_gen.generate("eng-both", fmt="both", generated_at=_FIXED_TIME)
    assert [entry["name"] for entry in result["artifacts"]] == [
        report_gen.REPORT_NAME,
        report_gen.REPORT_HTML_NAME,
    ]
    assert result["artifact"]["name"] == report_gen.REPORT_NAME
    assert artifact_store.resolve("eng-both", report_gen.REPORT_NAME).is_file()
    assert artifact_store.resolve("eng-both", report_gen.REPORT_HTML_NAME).is_file()


def test_generate_default_stays_markdown_only(staging):
    _append_example_finding("eng-default")
    result = report_gen.generate("eng-default", generated_at=_FIXED_TIME)
    assert result["artifact"]["name"] == report_gen.REPORT_NAME
    assert result["format"] == "md"
    assert artifact_store.resolve("eng-default", report_gen.REPORT_NAME).is_file()
    assert not artifact_store.resolve("eng-default", report_gen.REPORT_HTML_NAME).exists()


def test_main_html_format_is_deterministic_with_fixed_timestamp(staging, capsys):
    _append_example_finding("eng-cli")
    argv = ["--engagement", "eng-cli", "--format", "html", "--generated-at", _FIXED_TIME]
    assert report_gen.main(argv) == 0
    first_out = capsys.readouterr().out
    assert report_gen.main(argv) == 0
    second_out = capsys.readouterr().out
    assert "report generated: eng-cli/pentest-report.html" in first_out
    assert first_out.split("sha256=")[-1] == second_out.split("sha256=")[-1]


def test_main_both_prints_both_artifact_lines(staging, capsys):
    _append_example_finding("eng-cli-both")
    assert report_gen.main(["--engagement", "eng-cli-both", "--format", "both"]) == 0
    out = capsys.readouterr().out
    assert "eng-cli-both/pentest-report.md" in out
    assert "eng-cli-both/pentest-report.html" in out
