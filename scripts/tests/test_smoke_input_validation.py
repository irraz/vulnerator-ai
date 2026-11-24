"""Tests for smoke input validation and strict suite enforcement."""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]
GUARD = SCRIPTS / "smoke.py"


def _load_smoke():
    spec = importlib.util.spec_from_file_location("smoke", GUARD)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


smoke = _load_smoke()


def test_malformed_config_is_reported_not_raised(tmp_path, monkeypatch, capsys):
    bad = tmp_path / "config.yaml"
    bad.write_text("mcp_servers: [unclosed\n", encoding="utf-8")
    monkeypatch.setattr(smoke, "CONFIG", bad)

    report = smoke.Report()
    smoke.check_contracts(report)

    out = capsys.readouterr().out
    assert report.failures >= 1
    assert "invalid YAML" in out


def test_non_mapping_yaml_is_reported(tmp_path, monkeypatch, capsys):
    bad = tmp_path / "config.yaml"
    bad.write_text("- just\n- a list\n", encoding="utf-8")
    monkeypatch.setattr(smoke, "CONFIG", bad)

    report = smoke.Report()
    smoke.check_contracts(report)

    out = capsys.readouterr().out
    assert report.failures >= 1
    assert "expected a mapping" in out


def test_invalid_utf8_map_is_reported(tmp_path, monkeypatch, capsys):
    bad = tmp_path / "ARCHITECTURE_MAP.md"
    bad.write_bytes(b"\xff\xfe\x00\x01")
    monkeypatch.setattr(smoke, "MAP", bad)

    report = smoke.Report()
    smoke.check_map(report)

    out = capsys.readouterr().out
    assert report.failures >= 1
    assert "cannot read" in out


def _suite_env(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    root.mkdir()
    monkeypatch.setattr(smoke, "ROOT", root)
    monkeypatch.setattr(smoke, "find_uv", lambda: None)
    return root


def test_strict_mode_fails_on_missing_suite(tmp_path, monkeypatch, capsys):
    _suite_env(tmp_path, monkeypatch)
    monkeypatch.setattr(smoke, "SUITES", (("missing/tests", ["pytest"]),))

    report = smoke.Report()
    smoke.check_tests(report, strict_suites=True)

    out = capsys.readouterr().out
    assert report.failures >= 1
    assert "missing suite directory" in out


def test_missing_suite_always_fails(tmp_path, monkeypatch, capsys):
    """A missing suite is a failure in every mode: local runner == CI gate."""
    _suite_env(tmp_path, monkeypatch)
    monkeypatch.setattr(smoke, "SUITES", (("missing/tests", ["pytest"]),))

    for strict in (False, True):
        report = smoke.Report()
        smoke.check_tests(report, strict_suites=strict)
        assert report.failures >= 1, strict
        assert "missing suite directory" in capsys.readouterr().out


def test_strict_mode_fails_when_no_tests_are_collected(tmp_path, monkeypatch, capsys):
    root = _suite_env(tmp_path, monkeypatch)
    (root / "empty").mkdir()
    monkeypatch.setattr(smoke, "SUITES", (("empty", ["pytest"]),))
    monkeypatch.setattr(
        smoke,
        "run_suite",
        lambda suite, deps, uv: (5, {"passed": 0, "failed": 0, "skipped": 0, "errors": 0}, ""),
    )

    for strict in (False, True):
        report = smoke.Report()
        smoke.check_tests(report, strict_suites=strict)
        assert report.failures >= 1, strict

    out = capsys.readouterr().out
    assert "no tests collected" in out


# --------------------------------------------------------------------------- readers
#
# A corrupted or syntactically invalid file must produce a deterministic failure
# (file + reason), never a traceback. These tests exercise the three readers that
# parse the MCP servers / the docker tree.


def _fake_root(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    root.mkdir()
    monkeypatch.setattr(smoke, "ROOT", root)
    return root


def test_ast_tool_decorations_reports_invalid_utf8(tmp_path, monkeypatch, capsys):
    root = _fake_root(tmp_path, monkeypatch)
    target = root / "server.py"
    target.write_bytes(b"\xff\xfe\x00\x01")

    report = smoke.Report()
    assert smoke.ast_tool_decorations(report, "tools", target) == []

    out = capsys.readouterr().out
    assert report.failures == 1
    assert "cannot read server.py" in out
    assert "UnicodeDecodeError" in out
    assert "Traceback" not in out


def test_ast_tool_decorations_reports_syntax_error(tmp_path, monkeypatch, capsys):
    root = _fake_root(tmp_path, monkeypatch)
    target = root / "server.py"
    target.write_text("def broken(:\n", encoding="utf-8")

    report = smoke.Report()
    assert smoke.ast_tool_decorations(report, "tools", target) == []

    out = capsys.readouterr().out
    assert report.failures == 1
    assert "invalid Python syntax" in out
    assert "Traceback" not in out


def test_tool_name_constants_reports_invalid_utf8(tmp_path, monkeypatch, capsys):
    root = _fake_root(tmp_path, monkeypatch)
    target = root / "server.py"
    target.write_bytes(b"\xff\xfe\x00\x01")

    report = smoke.Report()
    assert smoke.tool_name_constants(report, "tools", target) == []

    out = capsys.readouterr().out
    assert report.failures == 1
    assert "cannot read server.py" in out
    assert "Traceback" not in out


def test_module_imports_mcp_reports_syntax_error(tmp_path, monkeypatch, capsys):
    root = _fake_root(tmp_path, monkeypatch)
    target = root / "server.py"
    target.write_text("def broken(:\n", encoding="utf-8")

    report = smoke.Report()
    assert smoke.module_imports_mcp(report, "imports", target) is None

    out = capsys.readouterr().out
    assert report.failures == 1
    assert "invalid Python syntax" in out
    assert "Traceback" not in out


def test_corrupted_server_fails_the_tools_check(tmp_path, monkeypatch, capsys):
    """End to end: a corrupted kali server is a red tools check, no traceback."""
    root = _fake_root(tmp_path, monkeypatch)
    (root / "docker" / "kali").mkdir(parents=True)
    (root / "docker" / "mcp").mkdir(parents=True)
    (root / "docker" / "kali" / "kali_mcp_server.py").write_bytes(b"\xff\xfe\x00\x01")
    (root / "docker" / "mcp" / "vulnerator_mcp_server.py").write_text(
        "def ok():\n    pass\n", encoding="utf-8"
    )
    monkeypatch.setattr(smoke, "KALI_SERVER", root / "docker" / "kali" / "kali_mcp_server.py")
    monkeypatch.setattr(
        smoke, "VULN_SERVER", root / "docker" / "mcp" / "vulnerator_mcp_server.py"
    )

    report = smoke.Report()
    smoke.check_tools(report)

    out = capsys.readouterr().out
    assert report.failures >= 1
    assert "cannot read kali_mcp_server.py" in out
    assert "Traceback" not in out


def test_corrupted_server_fails_the_map_check(tmp_path, monkeypatch, capsys):
    """End to end: a corrupted kali server is a red map check, no traceback."""
    root = _fake_root(tmp_path, monkeypatch)
    (root / "docker" / "kali").mkdir(parents=True)
    (root / "docker" / "mcp").mkdir(parents=True)
    (root / "docker" / "kali" / "kali_mcp_server.py").write_bytes(b"\xff\xfe\x00\x01")
    (root / "docker" / "mcp" / "vulnerator_mcp_server.py").write_text(
        "def ok():\n    pass\n", encoding="utf-8"
    )
    monkeypatch.setattr(smoke, "KALI_SERVER", root / "docker" / "kali" / "kali_mcp_server.py")
    monkeypatch.setattr(
        smoke, "VULN_SERVER", root / "docker" / "mcp" / "vulnerator_mcp_server.py"
    )
    monkeypatch.setattr(smoke, "MAP", root / "ARCHITECTURE_MAP.md")
    (root / "ARCHITECTURE_MAP.md").write_text(
        "\n".join(f"## {n}." for n in range(1, 15)) + "\n", encoding="utf-8"
    )

    report = smoke.Report()
    smoke.check_map(report)

    out = capsys.readouterr().out
    assert report.failures >= 1
    assert "cannot read kali_mcp_server.py" in out
    assert "Traceback" not in out


def test_syntax_error_server_fails_the_imports_check(tmp_path, monkeypatch, capsys):
    """End to end: a syntactically invalid module is a red imports check."""
    root = _fake_root(tmp_path, monkeypatch)
    module = root / "docker" / "mcp" / "mcp_tool_logic.py"
    module.parent.mkdir(parents=True, exist_ok=True)
    module.write_text("def broken(:\n", encoding="utf-8")

    report = smoke.Report()
    smoke.check_imports(report)

    out = capsys.readouterr().out
    assert report.failures >= 1
    assert "invalid Python syntax" in out
    # The parse failure must be reported deterministically; only the later SDK-free
    # import probe (which genuinely imports the module) may show a traceback.
    parse_lines = [l for l in out.splitlines() if "invalid Python syntax" in l]
    assert parse_lines
    assert "Traceback" not in parse_lines[0]
    assert "could not be parsed" in out


# --------------------------------------------------------------------------- runner
#
# scripts/run_tests.sh must fail (exit 1) when a suite directory is missing, so the
# local runner reports exactly what CI enforces with --strict-suites.


RUNNER = SCRIPTS / "run_tests.sh"


def test_runner_missing_suite_exits_1(tmp_path):
    """The runner exits 1 and never prints 'all N suites pass' for a missing suite."""
    sandbox = tmp_path / "runner"
    sandbox.mkdir()
    script = sandbox / "run_tests.sh"
    source = RUNNER.read_text(encoding="utf-8")
    marker = 'SUITES=(\n  "agent-ooda/tests|pytest;pyyaml"'
    assert marker in source
    # Replace the whole suite list with a single absent suite, so the probe does not
    # depend on which sibling suites happen to exist in the sandbox.
    start = source.index("SUITES=(")
    end = source.index(")\n", start) + 2
    script.write_text(
        source[:start] + 'SUITES=(\n  "absent-suite|pytest"\n)\n' + source[end:],
        encoding="utf-8",
    )
    proc = subprocess.run(
        ["bash", str(script)],
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", "UV_BIN": "/nonexistent-uv"},
    )
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "absent-suite: missing suite directory" in proc.stdout
    assert "suites absent  : 1" in proc.stdout
    assert "all 0 suites pass" not in proc.stdout


# --- labs documentation index -------------------------------------------------

LABS_COMPOSE = "services: {}\n"


def _labs_sandbox(tmp_path: Path) -> Path:
    """A sandbox labs/ tree: one real lab, one non-lab dir, one build-noise dir."""
    labs = tmp_path / "labs"
    for name in ("alpha-lab", "__pycache__", "notes"):
        (labs / name).mkdir(parents=True)
    (labs / "alpha-lab" / "docker-compose.yml").write_text(LABS_COMPOSE, encoding="utf-8")
    (labs / "alpha-lab" / "README.md").write_text("# Alpha\n", encoding="utf-8")
    return labs


def test_only_directories_with_compose_count_as_labs(tmp_path):
    labs = _labs_sandbox(tmp_path)
    assert smoke.lab_dirs(labs) == ["alpha-lab"]


def test_undocumented_lab_and_broken_link_are_detected(tmp_path):
    labs = _labs_sandbox(tmp_path)

    assert smoke.labs_index_issues("# Labs\n", labs) == (["alpha-lab"], [])

    text = "# Labs\n\n`alpha-lab/` [broken](alpha-lab/missing.md)\n"
    assert smoke.labs_index_issues(text, labs) == ([], ["alpha-lab/missing.md"])

    documented = "# Labs\n\n`alpha-lab/` [ok](alpha-lab/docker-compose.yml)\n"
    assert smoke.labs_index_issues(documented, labs) == ([], [])

    linked_only = "# Labs\n\n[the lab](alpha-lab/README.md)\n"
    assert smoke.labs_index_issues(linked_only, labs) == ([], [])


def test_check_labs_index_fails_on_missing_coverage(tmp_path, monkeypatch, capsys):
    labs = _labs_sandbox(tmp_path)
    index = labs / "README.md"
    index.write_text("# Labs\n\n`alpha-lab/`\n", encoding="utf-8")
    monkeypatch.setattr(smoke, "LABS_INDEX", index)

    report = smoke.Report()
    smoke.check_labs_index(report)
    assert report.failures == 0
    assert "documents all 1 labs" in capsys.readouterr().out

    index.write_text("# Labs\n\nNo labs listed.\n", encoding="utf-8")
    report = smoke.Report()
    smoke.check_labs_index(report)
    out = capsys.readouterr().out
    assert report.failures >= 1
    assert "alpha-lab" in out


def test_check_labs_index_reports_a_missing_index(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(smoke, "LABS_INDEX", tmp_path / "absent.md")

    report = smoke.Report()
    smoke.check_labs_index(report)

    out = capsys.readouterr().out
    assert report.failures >= 1
    assert "missing" in out
