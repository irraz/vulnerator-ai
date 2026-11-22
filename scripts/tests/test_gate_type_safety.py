"""Tests for the deterministic type-safety gate of the smoke checker.

A syntactically valid YAML file can still carry a list where a mapping is
expected, or an int where a list belongs. These tests pin the contract: every
such case is a red failure with the file, the field and the expected/received
type, never a traceback.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1]
SMOKE = SCRIPTS / "smoke.py"
GUARD = SCRIPTS / "check_language.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


smoke = _load("smoke", SMOKE)
guard = _load("check_language", GUARD)


def _replace_block(path: Path, key: str, new_text: str) -> None:
    """Replaces a top-level `key:` block (until the next unindented line)."""
    lines = path.read_text(encoding="utf-8").splitlines()
    idx = [n for n, line in enumerate(lines) if line == f"{key}:"]
    assert len(idx) == 1, f"{key!r} block not unique in {path}: {idx}"
    i = idx[0]
    j = len(lines)
    for n in range(i + 1, len(lines)):
        if lines[n].strip() and not lines[n][0].isspace():
            j = n
            break
    path.write_text(
        "\n".join(lines[:i] + new_text.splitlines() + lines[j:]) + "\n",
        encoding="utf-8",
    )


# --------------------------------------------------------------------------- config


CONFIG_CASES = [
    ("mcp_servers: [kali, playwright]", "mcp_servers must be a mapping, got list"),
    ("mcp_servers:\n  kali: [x]", "kali must be a mapping, got list"),
    ("platforms: [x]", "platforms must be a mapping, got list"),
    ("platforms:\n  api_server: [x]", "api_server must be a mapping, got list"),
    ("model: [x]", "model must be a mapping, got list"),
]


@pytest.mark.parametrize(("block", "expected"), CONFIG_CASES)
def test_config_type_errors_are_reported(
    tmp_path, monkeypatch, capsys, block, expected
):
    config = tmp_path / "config.yaml"
    config.write_text(smoke.CONFIG.read_text(encoding="utf-8"), encoding="utf-8")
    _replace_block(config, block.split(":", 1)[0], block)
    monkeypatch.setattr(smoke, "CONFIG", config)

    report = smoke.Report()
    smoke.check_contracts(report)

    out = capsys.readouterr().out
    assert report.failures >= 1
    assert expected in out
    assert "Traceback" not in out


# --------------------------------------------------------------------------- compose


COMPOSE_CASES = [
    ("volumes: 5\n", "volumes must be a mapping, got int"),
    ("services: 5\n", "services must be a mapping, got int"),
    ("services: [a, b]\n", "services must be a mapping, got list"),
    ("services:\n  kali: [x]\n", "services.kali must be a mapping, got list"),
    ("services:\n  1: {}\n", "services keys must be strings, got 1 (int)"),
]


@pytest.mark.parametrize(("text", "expected"), COMPOSE_CASES)
def test_compose_type_errors_are_reported(
    tmp_path, monkeypatch, capsys, text, expected
):
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(text, encoding="utf-8")
    monkeypatch.setattr(smoke, "COMPOSE", compose)

    report = smoke.Report()
    smoke.check_contracts(report)

    out = capsys.readouterr().out
    assert report.failures >= 1
    assert expected in out
    assert "Traceback" not in out


def test_compose_ports_type_error_is_reported(tmp_path, monkeypatch, capsys):
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        "services:\n  ooda-agent:\n    ports: 5\nvolumes: {}\n", encoding="utf-8"
    )
    monkeypatch.setattr(smoke, "COMPOSE", compose)

    report = smoke.Report()
    smoke.check_contracts(report)

    out = capsys.readouterr().out
    assert report.failures >= 1
    assert "services.ooda-agent.ports must be a sequence, got int" in out
    assert "Traceback" not in out


def test_compose_depends_on_type_error_is_reported(tmp_path, monkeypatch, capsys):
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        "services:\n  ooda-agent:\n    depends_on: [kali]\n    ports: [\"8642:8642\"]\n"
        "volumes: {}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(smoke, "COMPOSE", compose)

    report = smoke.Report()
    smoke.check_contracts(report)

    out = capsys.readouterr().out
    assert report.failures >= 1
    assert "services.ooda-agent.depends_on must be a mapping, got list" in out
    assert "Traceback" not in out


# --------------------------------------------------------------------------- bounds


def test_annex_line_out_of_range_is_reported(tmp_path, monkeypatch, capsys):
    """A map row citing a line the compose does not have is a red failure."""
    text = smoke.MAP.read_text(encoding="utf-8")
    assert "`docker-compose.yml:25`" in text
    map_file = tmp_path / "ARCHITECTURE_MAP.md"
    map_file.write_text(
        text.replace("`docker-compose.yml:25`", "`docker-compose.yml:999999`", 1),
        encoding="utf-8",
    )
    monkeypatch.setattr(smoke, "MAP", map_file)

    report = smoke.Report()
    smoke.check_map(report)

    out = capsys.readouterr().out
    assert report.failures >= 1
    assert "cited line 999999 is out of range" in out
    assert "Traceback" not in out


def test_short_compose_cannot_be_indexed_by_the_map(tmp_path, monkeypatch, capsys):
    """A valid but shorter compose makes every cited line out of range."""
    compose = tmp_path / "docker-compose.yml"
    compose.write_text("services:\n  kali: {}\n", encoding="utf-8")
    monkeypatch.setattr(smoke, "COMPOSE", compose)

    report = smoke.Report()
    smoke.check_map(report)

    out = capsys.readouterr().out
    assert report.failures >= 1
    assert "is out of range" in out
    assert "Traceback" not in out


# --------------------------------------------------------------------------- baseline


def test_invalid_baseline_json_is_an_error_not_a_traceback(tmp_path, capsys):
    bad = tmp_path / "baseline.json"
    bad.write_text("not json{", encoding="utf-8")

    rc = guard.main(["--all", "--baseline", str(bad)])

    captured = capsys.readouterr()
    assert rc == 1
    assert "invalid baseline JSON" in captured.err
    assert "line 1 column 1" in captured.err
    assert "Traceback" not in captured.out + captured.err


def test_malformed_baseline_entries_are_an_error(tmp_path, capsys):
    bad = tmp_path / "baseline.json"
    bad.write_text(
        json.dumps(
            {
                "version": guard.BASELINE_VERSION,
                "regex": guard.NON_ENGLISH_RE.pattern,
                "normalization": guard.NORMALIZATION,
                "entries": {"deadbeef": {"count": "1"}},
            }
        ),
        encoding="utf-8",
    )

    rc = guard.main(["--all", "--baseline", str(bad)])

    captured = capsys.readouterr()
    assert rc == 1
    assert "integer 'count'" in captured.err
    assert "Traceback" not in captured.out + captured.err
