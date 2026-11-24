#!/usr/bin/env python3
"""Smoke test for the vulnerator-ai worktree (contracts, tools, map, imports and tests).

It is a homegrown checker, not a product test: it validates that the declarative
wiring (config.yaml + docker-compose.yml), the real tool surface (by AST, WITHOUT
importing the servers), the annexes of ARCHITECTURE_MAP.md, the SDK-free purity
of the logic modules and the labs documentation index still match what the map says.

Usage:
    python3 scripts/smoke.py            # --quick (static + tests)
    python3 scripts/smoke.py --check    # only contracts/tools/map/imports (alias of --static)
    python3 scripts/smoke.py --static   # only contracts/tools/map/imports
    python3 scripts/smoke.py --tests    # only the suites in a subprocess
    python3 scripts/smoke.py --quick    # static + tests (fast gate)

Discipline:
  - NEVER imports docker/kali/kali_mcp_server.py or docker/mcp/vulnerator_mcp_server.py:
    the tools are read with `ast` (@mcp.tool decorators and *_TOOL_NAME constants).
  - NEVER uses --import-mode=importlib.
  - The test subprocesses run with `env -u PYTHONPATH` and cwd=root.
"""

from __future__ import annotations

import argparse
import ast
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

CONFIG = ROOT / "agent-ooda" / "profile" / "config.yaml"
COMPOSE = ROOT / "docker-compose.yml"
KALI_SERVER = ROOT / "docker" / "kali" / "kali_mcp_server.py"
VULN_SERVER = ROOT / "docker" / "mcp" / "vulnerator_mcp_server.py"
MAP = ROOT / "ARCHITECTURE_MAP.md"
RUN_TESTS = ROOT / "scripts" / "run_tests.sh"
LABS_INDEX = ROOT / "labs" / "README.md"

GREEN, RED, WARN = "✅", "❌", "⚠️"

# PURE LOGIC modules that must not depend on the `mcp` SDK (they are really imported).
SDK_FREE_IMPORT = [
    ROOT / "docker" / "mcp" / "mcp_tool_logic.py",
    ROOT / "docker" / "kali" / "scope_guard.py",
    ROOT / "docker" / "kali" / "tool_streaming.py",
    ROOT / "docker" / "kali" / "finding_store.py",
]

# The suites and the dependencies each one needs in the test interpreter.
# A suite that does not exist is a FAILURE (not a warning): the local runner must
# see exactly what the CI gate sees.
SUITES: list[tuple[str, list[str]]] = [
    ("agent-ooda/tests", ["pytest", "pyyaml"]),
    ("docker/kali/tests", ["pytest"]),
    ("docker/mcp/tests", ["pytest", "anyio", "httpx", "mcp>=1.28,<2"]),
    (
        "docker/web/tests",
        [
            "pytest",
            "anyio",
            "httpx",
            "starlette>=0.52.1,<1",
            "uvicorn>=0.54.0,<1",
            "websockets>=13.0,<16",
        ],
    ),
    ("docker/browser-view/tests", ["pytest"]),
    ("scripts/tests", ["pytest", "pyyaml"]),
]

EXPECTED_MCP_SERVERS = ["kali", "playwright"]
EXPECTED_TOOLSETS = ["kali", "playwright", "todo", "kanban"]

# The 14 numbered sections of the map: the gate requires them to exist, exactly once
# and in order (renaming a section cannot go unnoticed).
REQUIRED_SECTIONS = [f"## {n}." for n in range(1, 15)]

# Drift strings the map must no longer contain (branches and outdated counts).
FORBIDDEN_DRIFT = ("absent in this branch", "5 suites", "4 outdated tests")
EXPECTED_COMPOSE_SERVICES = [
    "kali",
    "ooda-agent",
    "playwright-mcp",
    "vulnerator-mcp",
    "vulnerator-web",
    "browser-view",
    "caido-director",
    "caido-init",
    "caido",
]
EXPECTED_VOLUMES = [
    "hermes-data",
    "kali-artifacts",
    "caido-data",
    "vulnerator-web-data",
]
EXPECTED_WEB_PROFILE = ["vulnerator-web", "browser-view", "caido-director"]


class Report:
    """Section accumulator with failure and warning counters."""

    def __init__(self) -> None:
        self.failures = 0
        self.warnings = 0

    def ok(self, section: str, msg: str) -> None:
        print(f"[{section}] {GREEN} {msg}")

    def bad(self, section: str, msg: str) -> None:
        self.failures += 1
        print(f"[{section}] {RED} {msg}")

    def warn(self, section: str, msg: str) -> None:
        self.warnings += 1
        print(f"[{section}] {WARN} {msg}")


def read_text_file(rep: Report, section: str, path: Path) -> str | None:
    """Reads a required UTF-8 file, reporting failures instead of raising."""
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        rep.bad(section, f"cannot read {path.name}: {exc.__class__.__name__}")
        return None


def load_yaml_file(rep: Report, section: str, path: Path) -> dict | None:
    """Loads a required YAML mapping, reporting parse errors instead of raising."""
    text = read_text_file(rep, section, path)
    if text is None:
        return None
    import yaml

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        rep.bad(section, f"{path.name}: invalid YAML ({exc.__class__.__name__})")
        return None
    if not isinstance(data, dict):
        rep.bad(section, f"{path.name}: expected a mapping at the top level")
        return None
    return data


# --------------------------------------------------------------------------- type safety
#
# Every value read from config.yaml / docker-compose.yml is untrusted input: a
# syntactically valid YAML file can still carry a list where a mapping is
# expected, or an int where a list belongs. These helpers are the single
# deterministic gate: they check the type BEFORE .keys()/.get()/len()/items()/
# iteration and report a ❌ with the file, the field and the expected/received
# type. A wrong type yields None, so the caller skips the dependent checks
# instead of dumping a traceback.


def type_label(value: object) -> str:
    """Deterministic JSON-ish type name used in the failure messages."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, dict):
        return "map"
    if isinstance(value, list):
        return "list"
    if isinstance(value, str):
        return "str"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    return type(value).__name__


def require_mapping(
    rep: Report, section: str, where: str, field: str, value: object
) -> dict | None:
    """Returns `value` when it is a mapping, else reports and returns None."""
    if isinstance(value, dict):
        return value
    rep.bad(section, f"{where}: {field} must be a mapping, got {type_label(value)}")
    return None


def require_sequence(
    rep: Report, section: str, where: str, field: str, value: object
) -> list | None:
    """Returns `value` when it is a sequence, else reports and returns None."""
    if isinstance(value, list):
        return value
    rep.bad(section, f"{where}: {field} must be a sequence, got {type_label(value)}")
    return None


def field_mapping(
    rep: Report, section: str, where: str, parent: object, field: str
) -> dict | None:
    """Returns `parent[field]` as a mapping ({} when the field is absent).

    None means the parent is missing or the field has the wrong type: the
    failure is reported and the caller must skip the dependent checks.
    """
    if parent is None:
        return None
    if not isinstance(parent, dict):
        rep.bad(
            section,
            f"{where}: {field} parent must be a mapping, got {type_label(parent)}",
        )
        return None
    value = parent.get(field)
    if value is None:
        return {}
    return require_mapping(rep, section, where, field, value)


def mapping_names(
    rep: Report, section: str, where: str, field: str, mapping: dict
) -> list[str]:
    """Sorted string keys of a name mapping; non-string keys are reported."""
    names: list[str] = []
    bad: list[str] = []
    for key in mapping:
        if isinstance(key, str):
            names.append(key)
        else:
            bad.append(f"{key!r} ({type_label(key)})")
    if bad:
        rep.bad(
            section,
            f"{where}: {field} keys must be strings, got {', '.join(sorted(bad))}",
        )
    return sorted(names)


def require_line(
    rep: Report, section: str, where: str, lines: list[str], lineno: int
) -> str | None:
    """Returns the 1-based line of a file, reporting an out-of-range index."""
    if 1 <= lineno <= len(lines):
        return lines[lineno - 1]
    rep.bad(
        section,
        f"{where}: cited line {lineno} is out of range (file has {len(lines)} lines)",
    )
    return None


def annex_cited_lines(
    rep: Report,
    section: str,
    where: str,
    lines: list[str],
    rows: list[tuple[str, str, int]],
) -> tuple[dict[str, str], bool]:
    """Maps annex key -> cited line text, reporting out-of-range indexes.

    `complete` is False when at least one cited line does not exist, so the
    caller never prints a green summary over an already-reported failure.
    """
    hits: dict[str, str] = {}
    complete = True
    for key, _path, lineno in rows:
        text = require_line(rep, section, f"{where}:{key}", lines, lineno)
        if text is None:
            complete = False
        else:
            hits[key] = text
    return hits, complete


# --------------------------------------------------------------------------- utils


def ast_tool_decorations(rep: "Report | None", section: str, path: Path) -> list[tuple[str, int]]:
    """Returns [(name, line)] of the functions decorated with @mcp.tool(...).

    AST only: the file is NOT imported. The line is the `def` line (the decorator
    line is the immediately preceding one in this repo). A missing file, invalid
    UTF-8 or a syntax error is reported as a failure instead of raising, so a
    corrupted server never dumps a traceback.
    """
    try:
        src = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        if rep is not None:
            rep.bad(section, f"cannot read {path.name}: {exc.__class__.__name__}")
        return []
    try:
        tree = ast.parse(src, filename=str(path))
    except SyntaxError as exc:
        if rep is not None:
            rep.bad(
                section,
                f"{path.name}: invalid Python syntax at line {exc.lineno}: {exc.msg}",
            )
        return []
    found: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            name = None
            if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
                name = dec.func.attr
            elif isinstance(dec, ast.Attribute):
                name = dec.attr
            if name == "tool":
                found.append((node.name, node.lineno))
                break
    return found


def tool_name_constants(rep: "Report | None", section: str, path: Path) -> list[tuple[str, str]]:
    """*_TOOL_NAME = "name" constant (same source of truth as the decorators).

    A missing file or invalid UTF-8 is reported as a failure instead of raising.
    """
    try:
        src = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        if rep is not None:
            rep.bad(section, f"cannot read {path.name}: {exc.__class__.__name__}")
        return []
    return re.findall(
        r'^([A-Z][A-Z0-9_]*_TOOL_NAME)\s*=\s*["\']([^"\']+)["\']', src, re.M
    )


def module_imports_mcp(rep: "Report | None", section: str, path: Path) -> bool | None:
    """True if the module imports the `mcp` SDK (by AST, without importing it).

    None means the file could not be read or parsed: the caller reports the
    failure instead of a traceback.
    """
    try:
        src = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        if rep is not None:
            rep.bad(section, f"cannot read {path.name}: {exc.__class__.__name__}")
        return None
    try:
        tree = ast.parse(src, filename=str(path))
    except SyntaxError as exc:
        if rep is not None:
            rep.bad(
                section,
                f"{path.name}: invalid Python syntax at line {exc.lineno}: {exc.msg}",
            )
        return None
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(
                alias.name == "mcp" or alias.name.startswith("mcp.")
                for alias in node.names
            ):
                return True
        elif isinstance(node, ast.ImportFrom):
            if node.module and (node.module == "mcp" or node.module.startswith("mcp.")):
                return True
    return False


def find_uv() -> str | None:
    """Locates the uv binary (env UV_BIN > PATH > fixed environment path)."""
    env_uv = os.environ.get("UV_BIN")
    if env_uv and Path(env_uv).exists():
        return env_uv
    which = shutil.which("uv")
    if which:
        return which
    fixed = "/home/irraz/.hermes/tools/uv-0.13.5-linux-x64/uv"
    if Path(fixed).exists():
        return fixed
    return None


def clean_env() -> dict[str, str]:
    """Subprocess environment WITHOUT PYTHONPATH (it contaminates with mcp 2.3.0)."""
    return {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}


# --------------------------------------------------------------------------- contracts


def check_contracts(rep: Report) -> None:
    section = "contracts"

    if not CONFIG.exists() or not COMPOSE.exists():
        rep.bad(
            section,
            f"missing files: config={CONFIG.exists()} compose={COMPOSE.exists()}",
        )
        return

    cfg = load_yaml_file(rep, section, CONFIG)
    compose = load_yaml_file(rep, section, COMPOSE)
    if cfg is None or compose is None:
        return

    # --- config.yaml: the only two MCPs and their URLs -------------------------
    servers = require_mapping(
        rep, section, "config.yaml", "mcp_servers", cfg.get("mcp_servers")
    )
    if servers is not None:
        names = list(servers.keys())
        if names == EXPECTED_MCP_SERVERS:
            rep.ok(section, f"config.yaml mcp_servers = {names}")
        else:
            rep.bad(
                section,
                f"config.yaml mcp_servers = {names} (expected {EXPECTED_MCP_SERVERS})",
            )

        kali_cfg = field_mapping(rep, section, "config.yaml", servers, "kali")
        if kali_cfg is not None:
            if kali_cfg.get("url") == "http://kali:8900":
                rep.ok(section, "config.yaml kali.url = http://kali:8900")
            else:
                rep.bad(section, f"config.yaml kali.url = {kali_cfg.get('url')!r}")

            # No tools.include: the server is the source of truth.
            kali_tools_cfg = field_mapping(
                rep, section, "config.yaml", kali_cfg, "tools"
            )
            if kali_tools_cfg is not None:
                if "include" not in kali_tools_cfg:
                    rep.ok(
                        section,
                        "config.yaml kali.tools has no 'include' "
                        "(no whitelist: the server wins)",
                    )
                else:
                    rep.bad(
                        section,
                        "config.yaml kali.tools.include present (it must be absent)",
                    )

        pw_cfg = field_mapping(rep, section, "config.yaml", servers, "playwright")
        if pw_cfg is not None:
            if pw_cfg.get("url") == "http://playwright-mcp:8931/mcp":
                rep.ok(
                    section, "config.yaml playwright.url = http://playwright-mcp:8931/mcp"
                )
            else:
                rep.bad(section, f"config.yaml playwright.url = {pw_cfg.get('url')!r}")

    toolsets = require_sequence(
        rep, section, "config.yaml", "toolsets", cfg.get("toolsets")
    )
    if toolsets is not None:
        if toolsets == EXPECTED_TOOLSETS:
            rep.ok(section, f"config.yaml toolsets = {EXPECTED_TOOLSETS}")
        else:
            rep.bad(section, f"config.yaml toolsets = {toolsets!r}")

    platforms = require_mapping(
        rep, section, "config.yaml", "platforms", cfg.get("platforms")
    )
    api = field_mapping(rep, section, "config.yaml", platforms, "api_server")
    if api is not None:
        if api.get("enabled") is True and api.get("port") == 8642:
            rep.ok(section, "config.yaml platforms.api_server enabled=True port=8642")
        else:
            rep.bad(section, f"config.yaml platforms.api_server = {api!r}")

    model = require_mapping(rep, section, "config.yaml", "model", cfg.get("model"))
    if model is not None:
        if model.get("default") == "mistralai/mistral-large-4-0":
            rep.ok(section, "config.yaml model.default = mistralai/mistral-large-4-0")
        else:
            rep.bad(section, f"config.yaml model.default = {model.get('default')!r}")

    config_raw = read_text_file(rep, section, CONFIG)
    if config_raw is None:
        return
    if "--yolo" not in config_raw:
        rep.ok(section, "config.yaml without '--yolo'")
    else:
        rep.bad(section, "config.yaml contains '--yolo' (forbidden)")

    # --- docker-compose.yml: 9 services, 4 volumes, profiles, depends ---
    services = require_mapping(
        rep, section, "docker-compose.yml", "services", compose.get("services")
    )
    volumes = require_mapping(
        rep, section, "docker-compose.yml", "volumes", compose.get("volumes")
    )

    if services is not None:
        service_names = mapping_names(
            rep, section, "docker-compose.yml", "services", services
        )
        if len(services) == 9 and service_names == sorted(EXPECTED_COMPOSE_SERVICES):
            rep.ok(
                section, f"compose services = 9 ({', '.join(service_names)})"
            )
        else:
            rep.bad(section, f"compose services = {service_names}")

    if volumes is not None:
        volume_names = mapping_names(
            rep, section, "docker-compose.yml", "volumes", volumes
        )
        if volume_names == sorted(EXPECTED_VOLUMES):
            rep.ok(section, f"compose volumes = {volume_names}")
        else:
            rep.bad(section, f"compose volumes = {volume_names}")

    if services is not None:
        web_profile: list[str] = []
        for name, svc_value in services.items():
            if not isinstance(name, str):
                # Already reported by mapping_names: never mix key types.
                continue
            svc = require_mapping(
                rep, section, "docker-compose.yml", f"services.{name}", svc_value
            )
            if svc is None:
                continue
            raw_profiles = svc.get("profiles")
            if raw_profiles is None:
                continue
            profiles = require_sequence(
                rep,
                section,
                "docker-compose.yml",
                f"services.{name}.profiles",
                raw_profiles,
            )
            if profiles is not None and "web" in profiles:
                web_profile.append(name)
        web_profile.sort()
        if web_profile == sorted(EXPECTED_WEB_PROFILE):
            rep.ok(section, f"compose profile 'web' = {sorted(EXPECTED_WEB_PROFILE)}")
        else:
            rep.bad(section, f"compose profile 'web' = {web_profile}")

    ooda = field_mapping(rep, section, "docker-compose.yml", services, "ooda-agent")
    if ooda is not None:
        depends = require_mapping(
            rep,
            section,
            "docker-compose.yml",
            "services.ooda-agent.depends_on",
            ooda.get("depends_on"),
        )
        if depends is not None:
            kali_dep = field_mapping(
                rep, section, "docker-compose.yml", depends, "kali"
            )
            pw_dep = field_mapping(
                rep, section, "docker-compose.yml", depends, "playwright-mcp"
            )
            if (
                kali_dep is not None
                and pw_dep is not None
                and kali_dep.get("condition") == "service_healthy"
                and pw_dep.get("condition") == "service_healthy"
            ):
                rep.ok(
                    section,
                    "compose ooda-agent depends_on kali+playwright-mcp "
                    "(service_healthy)",
                )
            elif kali_dep is not None and pw_dep is not None:
                rep.bad(section, f"compose ooda-agent depends_on = {depends!r}")

        raw_ports = ooda.get("ports")
        if raw_ports is None:
            rep.bad(section, "compose ooda-agent does not publish 8642 ([])")
        else:
            ports = require_sequence(
                rep,
                section,
                "docker-compose.yml",
                "services.ooda-agent.ports",
                raw_ports,
            )
            if ports is not None:
                ooda_ports = [str(p) for p in ports]
                if any("8642" in p for p in ooda_ports):
                    rep.ok(
                        section,
                        f"compose ooda-agent publishes 8642 ({ooda_ports})",
                    )
                else:
                    rep.bad(
                        section,
                        f"compose ooda-agent does not publish 8642 ({ooda_ports})",
                    )

    pw_svc = field_mapping(
        rep, section, "docker-compose.yml", services, "playwright-mcp"
    )
    if pw_svc is not None:
        if "ports" not in pw_svc:
            rep.ok(section, "compose playwright-mcp has no ports (internal network)")
        else:
            rep.bad(section, "compose playwright-mcp publishes ports")

    compose_raw = read_text_file(rep, section, COMPOSE)
    if compose_raw is None:
        return
    if "--yolo" not in compose_raw:
        rep.ok(section, "compose without '--yolo'")
    else:
        rep.bad(section, "compose contains '--yolo' (forbidden)")


# --------------------------------------------------------------------------- tools


def check_tools(rep: Report) -> None:
    section = "tools"

    if not KALI_SERVER.exists() or not VULN_SERVER.exists():
        rep.bad(section, "the MCP servers are missing")
        return

    kali_tools = ast_tool_decorations(rep, section, KALI_SERVER)
    vuln_tools = ast_tool_decorations(rep, section, VULN_SERVER)
    # The constants live in the same file as the decorators: reading them again
    # would duplicate the same failure when that file is unreadable.
    kali_consts = (
        [] if not kali_tools else tool_name_constants(rep, section, KALI_SERVER)
    )

    # A file that could not be read or parsed is already a reported failure; the
    # count checks below would only add noise.
    if not kali_tools:
        # The kali file could not be read/parsed (already reported): only the vuln
        # count check still makes sense.
        if len(vuln_tools) == 6:
            rep.ok(
                section,
                f"vulnerator_mcp_server.py: 6 @mcp.tool by AST ({[n for n, _ in vuln_tools]})",
            )
        else:
            rep.bad(
                section,
                f"vulnerator_mcp_server.py: {len(vuln_tools)} @mcp.tool by AST (expected 6)",
            )
        return

    if len(kali_tools) == 21:
        rep.ok(
            section,
            f"kali_mcp_server.py: 21 @mcp.tool by AST (lines {[l for _, l in kali_tools]})",
        )
    else:
        rep.bad(
            section,
            f"kali_mcp_server.py: {len(kali_tools)} @mcp.tool by AST (expected 21)",
        )

    # 20 *_TOOL_NAME constants: they cover all the tools except `server_info`, which
    # uses the plain @mcp.tool() decorator (without name=) and takes the function name.
    tool_names = {n for n, _ in kali_tools}
    const_names = {n for _, n in kali_consts}
    if const_names == tool_names - {"server_info"}:
        rep.ok(
            section,
            "kali_mcp_server.py: 20 *_TOOL_NAME constants cover the 20 tools with name=",
        )
    else:
        rep.bad(
            section,
            f"kali_mcp_server.py: *_TOOL_NAME do not cover the tools (missing={sorted(tool_names - {'server_info'} - const_names)} "
            f"extra={sorted(const_names - tool_names)})",
        )

    if len(vuln_tools) == 6:
        rep.ok(
            section,
            f"vulnerator_mcp_server.py: 6 @mcp.tool by AST ({[n for n, _ in vuln_tools]})",
        )
    else:
        rep.bad(
            section,
            f"vulnerator_mcp_server.py: {len(vuln_tools)} @mcp.tool by AST (expected 6)",
        )

    # Guarantee: the servers were NOT imported to read the tools.
    leaked = [
        m for m in ("kali_mcp_server", "vulnerator_mcp_server") if m in sys.modules
    ]
    if not leaked:
        rep.ok(
            section, "servers read only by AST (not imported in this process)"
        )
    else:
        rep.bad(section, f"the servers were imported: {leaked}")


# --------------------------------------------------------------------------- map


ANNEX_A_ROW = re.compile(r"^\|\s*`([a-z_]+)`\s*\|\s*`([^`:]+):(\d+)`\s*\|\s*$")
ANNEX_B_ROW = re.compile(r"^\|\s*`([A-Za-z0-9._-]+)`\s*\|\s*`([^`:]+):(\d+)`\s*\|\s*$")
ANNEX_C_ROW = re.compile(r"^\|\s*\d+\s*\|\s*`([^`]+)`\s*\|")


def _section_lines(lines: list[str], start_marker: str, end_marker: str) -> list[str]:
    """Lines of a section: from start_marker (included) to end_marker (excluded)."""
    try:
        i = next(n for n, line in enumerate(lines) if line.startswith(start_marker))
    except StopIteration:
        return []
    j = len(lines)
    for n in range(i + 1, len(lines)):
        if lines[n].startswith(end_marker):
            j = n
            break
    return lines[i:j]


def _annex_tables(
    text: str,
) -> tuple[list[tuple[str, str, int]], list[tuple[str, str, int]], list[str]]:
    """Returns (Annex A rows, Annex B rows, Annex C suites).

    Annex A/B: (key, path, line). Annex C: name of each suite in order.
    """
    lines = text.splitlines()

    a_rows: list[tuple[str, str, int]] = []
    for line in _section_lines(lines, "## 11.", "## 12."):
        m = ANNEX_A_ROW.match(line.strip())
        if m:
            a_rows.append((m.group(1), m.group(2), int(m.group(3))))

    b_rows: list[tuple[str, str, int]] = []
    for line in _section_lines(lines, "## 12.", "## "):
        m = ANNEX_B_ROW.match(line.strip())
        if m:
            b_rows.append((m.group(1), m.group(2), int(m.group(3))))

    c_rows: list[str] = []
    for line in _section_lines(lines, "## 13.", "## 14."):
        m = ANNEX_C_ROW.match(line.strip())
        if m:
            c_rows.append(m.group(1))

    return a_rows, b_rows, c_rows


def check_map(rep: Report) -> None:
    section = "map"

    if not MAP.exists():
        rep.bad(section, f"missing {MAP.relative_to(ROOT)}")
        return

    text = read_text_file(rep, section, MAP)
    if text is None:
        return
    a_rows, b_rows, c_rows = _annex_tables(text)

    kali_ast = dict(ast_tool_decorations(rep, section, KALI_SERVER))
    vuln_ast = dict(ast_tool_decorations(rep, section, VULN_SERVER))

    annex_kali = {
        name: (path, line)
        for name, path, line in a_rows
        if path.startswith("docker/kali/")
    }
    annex_vuln = {
        name: (path, line)
        for name, path, line in a_rows
        if path.startswith("docker/mcp/")
    }

    if not kali_ast:
        # kali could not be read/parsed (already reported): the "extra" list of the
        # annex comparison would only repeat that same failure.
        rep.bad(section, "Annex A kali: the server could not be parsed")
    elif set(annex_kali) == set(kali_ast):
        bad_lines = [n for n, (p, l) in annex_kali.items() if kali_ast[n] != l]
        if not bad_lines:
            rep.ok(
                section,
                f"Annex A: {len(annex_kali)} kali tools match the AST (name+line)",
            )
        else:
            rep.bad(section, f"Annex A: wrong line in {bad_lines}")
    else:
        missing = sorted(set(kali_ast) - set(annex_kali))
        extra = sorted(set(annex_kali) - set(kali_ast))
        rep.bad(section, f"Annex A kali: missing={missing} extra={extra}")

    if not vuln_ast:
        rep.bad(section, "Annex A vulnerator-mcp: the server could not be parsed")
    elif set(annex_vuln) == set(vuln_ast):
        bad_lines = [n for n, (p, l) in annex_vuln.items() if vuln_ast[n] != l]
        if not bad_lines:
            rep.ok(
                section,
                f"Annex A: {len(annex_vuln)} vulnerator-mcp tools match the AST (name+line)",
            )
        else:
            rep.bad(section, f"Annex A: wrong line in {bad_lines}")
    else:
        missing = sorted(set(vuln_ast) - set(annex_vuln))
        extra = sorted(set(annex_vuln) - set(vuln_ast))
        rep.bad(section, f"Annex A vulnerator-mcp: missing={missing} extra={extra}")

    # Annex B: services and volumes against the real compose.
    compose = load_yaml_file(rep, section, COMPOSE)
    if compose is None:
        return
    compose_text = read_text_file(rep, section, COMPOSE)
    if compose_text is None:
        return
    services = require_mapping(
        rep, section, "docker-compose.yml", "services", compose.get("services")
    )
    volumes = require_mapping(
        rep, section, "docker-compose.yml", "volumes", compose.get("volumes")
    )
    compose_lines = compose_text.splitlines()

    service_names = (
        mapping_names(rep, section, "docker-compose.yml", "services", services)
        if services is not None
        else None
    )
    volume_names = (
        mapping_names(rep, section, "docker-compose.yml", "volumes", volumes)
        if volumes is not None
        else None
    )

    annex_services = [
        (k, p, l) for k, p, l in b_rows if service_names is not None and k in service_names
    ]
    annex_volumes = [
        (k, p, l) for k, p, l in b_rows if volume_names is not None and k in volume_names
    ]

    if service_names is not None and {k for k, _p, _l in annex_services} == set(service_names):
        hits, complete = annex_cited_lines(
            rep, section, "docker-compose.yml", compose_lines, annex_services
        )
        bad = [k for k, text in hits.items() if k not in text]
        if not complete:
            # The out-of-range citation is already reported; no green summary.
            pass
        elif not bad:
            rep.ok(
                section,
                f"Annex B: {len(hits)} services match the compose (name+line)",
            )
        else:
            rep.bad(section, f"Annex B: line does not contain the service {bad}")
    elif service_names is not None:
        missing = sorted(set(service_names) - {k for k, _p, _l in annex_services})
        extra = sorted({k for k, _p, _l in annex_services} - set(service_names))
        rep.bad(section, f"Annex B services: missing={missing} extra={extra}")

    if volume_names is not None and {k for k, _p, _l in annex_volumes} == set(volume_names):
        hits, complete = annex_cited_lines(
            rep, section, "docker-compose.yml", compose_lines, annex_volumes
        )
        bad = [k for k, text in hits.items() if k not in text]
        if not complete:
            pass
        elif not bad:
            rep.ok(
                section,
                f"Annex B: {len(hits)} volumes match the compose (name+line)",
            )
        else:
            rep.bad(section, f"Annex B: line does not contain the volume {bad}")
    elif volume_names is not None:
        missing = sorted(set(volume_names) - {k for k, _p, _l in annex_volumes})
        extra = sorted({k for k, _p, _l in annex_volumes} - set(volume_names))
        rep.bad(section, f"Annex B volumes: missing={missing} extra={extra}")

    # All the paths cited in the annexes must exist.
    broken = []
    for _key, path, _line in a_rows + b_rows:
        if not (ROOT / path).exists():
            broken.append(path)
    if not broken:
        rep.ok(section, "Annex A/B: all cited paths exist (test -e)")
    else:
        rep.bad(section, f"Annex A/B: broken paths {sorted(set(broken))}")

    # --- numbered sections: 14, exactly once and in order --------------------
    found_sections = [int(m.group(1)) for m in re.finditer(r"^## (\d+)\.", text, re.M)]
    expected_sections = list(range(1, len(REQUIRED_SECTIONS) + 1))
    if found_sections == expected_sections:
        rep.ok(
            section,
            f"map: {len(expected_sections)} numbered sections, exactly once and in order",
        )
    else:
        rep.bad(
            section,
            f"map: sections found {found_sections} (expected {expected_sections})",
        )

    # --- Annex C: rows == real suites ----------------------------------------
    suite_names = [name for name, _deps in SUITES]
    if len(c_rows) == len(SUITES) and set(c_rows) == set(suite_names):
        rep.ok(section, f"Annex C: {len(c_rows)} rows == {len(SUITES)} SUITES suites")
    else:
        rep.bad(
            section,
            f"Annex C: {len(c_rows)} rows ({c_rows}) vs SUITES {suite_names}",
        )

    # --- forbidden drift -----------------------------------------------------
    drift = [marker for marker in FORBIDDEN_DRIFT if marker in text]
    if not drift:
        rep.ok(section, "map: no forbidden drift strings")
    else:
        rep.bad(section, f"map: forbidden drift strings {drift}")

    # --- section 14: declared known debt -------------------------------------
    debt_text = "\n".join(_section_lines(text.splitlines(), "## 14.", "## 15."))
    if "## 14. Known debt" in text and (
        any(tok in debt_text for tok in ("black", "isort", "prettier"))
        or "no debt" in debt_text
    ):
        rep.ok(section, "map: '## 14. Known debt' present with declared debt")
    else:
        rep.bad(
            section,
            "map: '## 14. Known debt' missing or does not declare the pending reformat",
        )

    if "scripts/smoke.py" in text:
        rep.ok(section, "the map links scripts/smoke.py")
    else:
        rep.bad(section, "the map does not link scripts/smoke.py")


# --------------------------------------------------------------------------- imports


def check_imports(rep: Report) -> None:
    section = "imports"

    # 1) Only place that may import the SDK: the two control planes.
    offenders = []
    unreadable = []
    for path in sorted((ROOT / "docker").rglob("*.py")):
        if path in (KALI_SERVER, VULN_SERVER):
            continue
        imports = module_imports_mcp(rep, section, path)
        if imports is None:
            unreadable.append(str(path.relative_to(ROOT)))
        elif imports:
            offenders.append(str(path.relative_to(ROOT)))
    if unreadable:
        rep.bad(section, f"modules that could not be parsed: {unreadable}")
    if not offenders and not unreadable:
        rep.ok(
            section,
            "only kali_mcp_server.py and vulnerator_mcp_server.py import the 'mcp' SDK",
        )
    elif offenders:
        rep.bad(
            section, f"modules importing 'mcp' outside the servers: {offenders}"
        )

    # 2) The pure logic modules are really imported, without the SDK and without PYTHONPATH.
    missing = [str(p.relative_to(ROOT)) for p in SDK_FREE_IMPORT if not p.exists()]
    if missing:
        rep.bad(section, f"missing SDK-free modules: {missing}")
        return
    broken = [p for p in SDK_FREE_IMPORT if module_imports_mcp(None, section, p) is None]
    if broken:
        rep.bad(
            section,
            f"SDK-free modules that could not be parsed: "
            f"{[str(p.relative_to(ROOT)) for p in broken]}",
        )
        return

    script = (
        "import importlib, sys\n"
        f"sys.path.insert(0, {str(ROOT / 'docker' / 'mcp')!r})\n"
        f"sys.path.insert(0, {str(ROOT / 'docker' / 'kali')!r})\n"
        "for name in ['mcp_tool_logic', 'scope_guard', 'tool_streaming', 'finding_store']:\n"
        "    importlib.import_module(name)\n"
        "print('IMPORT_OK')\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(ROOT),
        env=clean_env(),
        capture_output=True,
        text=True,
    )
    if proc.returncode == 0 and "IMPORT_OK" in proc.stdout:
        rep.ok(
            section,
            "mcp_tool_logic/scope_guard/tool_streaming/finding_store import without the 'mcp' SDK",
        )
    else:
        rep.bad(section, f"SDK-free import failed: {proc.stderr.strip()[:300]}")


# --------------------------------------------------------------------------- tests


def _parse_pytest_summary(output: str) -> dict[str, int]:
    counts = {"passed": 0, "failed": 0, "skipped": 0, "errors": 0, "warnings": 0}
    for n, kind in re.findall(
        r"(\d+)\s+(passed|failed|skipped|errors?|warnings?)\b", output
    ):
        key = kind
        if kind.startswith("error"):
            key = "errors"
        elif kind.startswith("warning"):
            key = "warnings"
        counts[key] += int(n)
    return counts


def run_suite(
    suite: str, deps: list[str], uv: str | None
) -> tuple[int, dict[str, int], str]:
    if uv:
        cmd = [uv, "run", "--no-project", "--quiet"]
        for dep in deps:
            cmd += ["--with", dep]
        cmd += ["python3", "-m", "pytest", suite, "-p", "no:cacheprovider", "-q"]
    else:
        # Without uv (e.g. a CI with requirements-dev.txt already installed): direct pytest.
        cmd = [sys.executable, "-m", "pytest", suite, "-p", "no:cacheprovider", "-q"]
    proc = subprocess.run(
        cmd, cwd=str(ROOT), env=clean_env(), capture_output=True, text=True
    )
    output = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode, _parse_pytest_summary(output), output


def lab_dirs(labs_dir: Path) -> list[str]:
    """Immediate lab directories: the ones carrying a `docker-compose.yml`.

    Build noise (`__pycache__`) and other side directories are not labs.
    """
    return sorted(p.name for p in labs_dir.iterdir() if p.is_dir() and (p / "docker-compose.yml").exists())


def labs_index_issues(text: str, labs_dir: Path) -> tuple[list[str], list[str]]:
    """Returns (undocumented labs, broken relative links) for a labs index text."""
    names = lab_dirs(labs_dir)
    undocumented = [name for name in names if f"`{name}/`" not in text]

    broken: list[str] = []
    for target in re.findall(r"\[[^\]]+\]\(([^)]+)\)", text):
        if "://" in target or target.startswith("#"):
            continue
        path = (labs_dir / target.split("#")[0]).resolve()
        try:
            path.relative_to(labs_dir.resolve())
        except ValueError:
            continue
        if not path.exists():
            broken.append(target)

    return undocumented, sorted(set(broken))


def check_labs_index(rep: Report) -> None:
    """Every lab must be documented in `labs/README.md`, and its links must resolve."""
    section = "labs"

    try:
        label = str(LABS_INDEX.relative_to(ROOT))
    except ValueError:  # a test or an out-of-tree checkout pointed LABS_INDEX elsewhere
        label = str(LABS_INDEX)

    if not LABS_INDEX.exists():
        rep.bad(section, f"missing {label}")
        return

    text = read_text_file(rep, section, LABS_INDEX)
    if text is None:
        return

    undocumented, broken = labs_index_issues(text, LABS_INDEX.parent)
    if undocumented:
        rep.bad(section, f"labs/README.md does not document: {undocumented}")
    else:
        rep.ok(
            section,
            f"labs/README.md documents all {len(lab_dirs(LABS_INDEX.parent))} labs",
        )

    if broken:
        rep.bad(section, f"labs/README.md has unresolved links: {broken}")
    else:
        rep.ok(section, "labs/README.md relative links resolve")


def check_tests(rep: Report, strict_suites: bool = False) -> None:
    section = "tests"
    uv = find_uv()
    if uv is None:
        rep.warn(
            section,
            "uv not found: using direct pytest (requires requirements-dev.txt)",
        )
    else:
        print(f"[{section}] uv = {uv}")
    any_failed = False
    ran = 0
    absent = 0
    # A missing suite is always a failure: the local runner must see exactly what
    # the CI gate sees, so there is no permissive fallback. The absent count stays
    # in the summary for readability.
    for suite, deps in SUITES:
        if not (ROOT / suite).is_dir():
            absent += 1
            any_failed = True
            rep.bad(section, f"{suite}: missing suite directory")
            continue
        ran += 1
        rc, counts, output = run_suite(suite, deps, uv)
        parts = [
            f"{counts[k]} {k}"
            for k in ("passed", "failed", "skipped", "errors")
            if counts[k]
        ]
        summary = ", ".join(parts) if parts else "no count"
        if rc == 0:
            rep.ok(section, f"{suite}: {summary} (exit 0)")
        elif rc == 1:
            any_failed = True
            rep.bad(section, f"{suite}: {summary} (exit 1)")
        elif rc == 2:
            any_failed = True
            rep.bad(section, f"{suite}: collection error ({summary}, exit 2)")
        elif rc == 5:
            any_failed = True
            rep.bad(section, f"{suite}: no tests collected (exit 5)")
        else:
            any_failed = True
            rep.bad(section, f"{suite}: exit {rc} ({summary})")

        # On failure, dump the short test summary so nothing is hidden.
        if rc not in (0, 5):
            tail = [line for line in output.splitlines() if line.strip()][-12:]
            for line in tail:
                print(f"[{section}]     {line}")

    if any_failed:
        rep.warn(section, "there are red suites; dump each suite's summary")
    elif absent:
        rep.ok(section, f"{ran} suites pass; {absent} suite(s) absent in this branch")
    else:
        rep.ok(section, f"all {ran} suites pass")

# --------------------------------------------------------------------------- main


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Smoke test for the vulnerator-ai worktree"
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--check",
        action="store_true",
        help="alias of --static (contracts/tools/map/imports)",
    )
    group.add_argument(
        "--static", action="store_true", help="contracts + tools + map + imports"
    )
    group.add_argument("--tests", action="store_true", help="the suites in a subprocess")
    group.add_argument(
        "--quick", action="store_true", help="static + tests (fast gate)"
    )
    parser.add_argument(
        "--strict-suites",
        action="store_true",
        help="fail on missing or empty suites (used by the blocking CI gate)",
    )
    args = parser.parse_args()

    # No flags = fast gate (static + tests).
    do_static = (
        args.check
        or args.static
        or args.quick
        or not (args.check or args.static or args.tests or args.quick)
    )
    do_tests = (
        args.tests
        or args.quick
        or not (args.check or args.static or args.tests or args.quick)
    )

    rep = Report()
    print(f"vulnerator-ai smoke — root: {ROOT}")

    if do_static:
        check_contracts(rep)
        check_tools(rep)
        check_map(rep)
        check_imports(rep)
        check_labs_index(rep)
        print(
            f"[check] result: {GREEN if rep.failures == 0 else RED} "
            f"failures={rep.failures} warnings={rep.warnings}"
        )

    if do_tests:
        before = rep.failures
        check_tests(rep, args.strict_suites)
        print(
            f"[tests] result: {GREEN if rep.failures == before else RED} "
            f"accumulated failures={rep.failures} warnings={rep.warnings}"
        )

    return 1 if rep.failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
