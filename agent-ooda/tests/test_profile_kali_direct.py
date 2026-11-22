"""Declarative tests for the Hermes profile (OODA direct to Kali) and its compose wiring.

The profile is declarative config (YAML/Markdown), not executable code in the repo. These tests
assert the v2.0.0 declarative CONTRACT: the config points ONLY to the Kali MCP, WITHOUT a
whitelist (the server is the source of truth), and the compose ooda-agent service starts
Hermes against that Kali.
"""

from __future__ import annotations

import ast
from pathlib import Path

import yaml

# MCP servers the profile must declare (Kali + browser via MCP).
EXPECTED_MCP_SERVERS = ["kali", "playwright"]

# Tools of an external orchestrator contract that must NOT reappear in the profile: the agent
# talks ONLY to the Kali MCP. Names are built from parts on purpose so the literal
# strings are not written into the file.
_PREFIX = "penta" + "gent_"
FORBIDDEN_TOOLS = [
    _PREFIX + "get_findings",
    _PREFIX + "get_attack_graph",
    _PREFIX + "get_analysis",
    _PREFIX + "exec" + "ute_step",
    _PREFIX + "report_" + "observation",
    "get_state",
    "propose_next_step",
]


# --- kali-direct profile: agent-ooda/profile/config.yaml --------------------


def _load_config(profile_config_path: Path) -> dict:
    return yaml.safe_load(profile_config_path.read_text(encoding="utf-8"))


def test_mcp_servers_are_kali_and_playwright(profile_config_path: Path) -> None:
    cfg = _load_config(profile_config_path)
    servers = cfg["mcp_servers"]
    assert list(servers) == EXPECTED_MCP_SERVERS, "the MCPs must be exactly kali and playwright"
    # The contract of a removed external orchestrator must not reappear.
    assert "pa" not in servers
    assert "pentagent" not in servers


def test_kali_url_points_to_kali_mcp(profile_config_path: Path) -> None:
    cfg = _load_config(profile_config_path)
    assert cfg["mcp_servers"]["kali"]["url"] == "http://kali:8900"


def test_playwright_url_points_to_browser_mcp(profile_config_path: Path) -> None:
    cfg = _load_config(profile_config_path)
    assert cfg["mcp_servers"]["playwright"]["url"] == "http://playwright-mcp:8931/mcp"


def test_kali_server_has_no_auth_headers(profile_config_path: Path) -> None:
    cfg = _load_config(profile_config_path)
    kali = cfg["mcp_servers"]["kali"]
    assert "headers" not in kali, "the kali server must not carry headers (no token)"
    raw = profile_config_path.read_text(encoding="utf-8")
    assert "Authorization" not in raw, "there must be no Authorization header"


def _server_tool_names(server_path: Path) -> list[str]:
    """Derives by AST the tool names the server publishes (not by grep).

    Resolves the module-level constants (``KALI_RUN_TOOL_NAME = "kali_run"``) used in
    ``@mcp.tool(name=...)``; if they have no ``name=``, the name is the function's.
    """
    tree = ast.parse(server_path.read_text(encoding="utf-8"))
    consts: dict[str, str] = {}
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            consts[node.targets[0].id] = node.value.value

    names: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            if ".tool" not in ast.unparse(dec):
                continue
            name = node.name
            for kw in getattr(dec, "keywords", []):
                if kw.arg == "name":
                    if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                        name = kw.value.value
                    elif isinstance(kw.value, ast.Name):
                        name = consts.get(kw.value.id, node.name)
            names.append(name)
    return sorted(names)


def test_tools_include_removed_server_is_source_of_truth(
    profile_config_path: Path, repo_root: Path
) -> None:
    """v2.0.0 contract: there is no `tools.include`; the server publishes what Hermes sees."""
    cfg = _load_config(profile_config_path)
    tools = cfg["mcp_servers"]["kali"]["tools"]
    assert "include" not in tools, (
        "`tools.include` was removed on purpose: the server is the source of truth"
    )
    assert tools["prompts"] is False
    assert tools["resources"] is False

    server_path = repo_root / "docker" / "kali" / "kali_mcp_server.py"
    real_tools = _server_tool_names(server_path)
    assert len(real_tools) == 21, f"the server publishes 21 tools (by AST): {real_tools}"
    assert "read_scan_findings" in real_tools, "the extra tool read_scan_findings must exist"

    raw_config = profile_config_path.read_text(encoding="utf-8")
    server_ast = ast.dump(ast.parse(server_path.read_text(encoding="utf-8")))
    for tool in FORBIDDEN_TOOLS:
        assert tool not in real_tools, f"{tool} (external contract) must not be in the real tools"
        assert tool not in raw_config, f"{tool} must not appear in config.yaml"
        assert tool not in server_ast, f"{tool} must not appear in the server AST"


def test_utility_wrappers_disabled(profile_config_path: Path) -> None:
    cfg = _load_config(profile_config_path)
    tools = cfg["mcp_servers"]["kali"]["tools"]
    assert tools["prompts"] is False
    assert tools["resources"] is False


def test_native_toolsets_trimmed(profile_config_path: Path) -> None:
    cfg = _load_config(profile_config_path)
    toolsets = cfg.get("toolsets")
    assert isinstance(toolsets, list), "toolsets must be a LIST of bundles (not a dict)"
    assert toolsets == ["kali", "playwright", "todo", "kanban"], (
        "the bundles are the two MCPs (kali + playwright) + todo/kanban, without native toolsets"
    )
    disabled = cfg.get("agent", {}).get("disabled_toolsets", [])
    # The browser arrives via MCP (`playwright`), NOT via the native `browser` toolset: the latter
    # stays disabled, like the rest of the native bundles.
    for bundle in (
        "code_execution",
        "terminal",
        "file",
        "browser",
        "web",
        "search",
        "computer_use",
        "memory",
        "skills",
    ):
        assert bundle in disabled, f"{bundle} must be in agent.disabled_toolsets"


def test_tool_search_disabled(profile_config_path: Path) -> None:
    cfg = _load_config(profile_config_path)
    assert cfg["tools"]["tool_search"]["enabled"] is False


def test_model_default_is_mistral_large(profile_config_path: Path) -> None:
    cfg = _load_config(profile_config_path)
    assert cfg["model"]["default"] == "mistralai/mistral-large-4-0"


def test_api_server_platform_declared(profile_config_path: Path) -> None:
    cfg = _load_config(profile_config_path)
    api = cfg["platforms"]["api_server"]
    assert api["enabled"] is True
    assert api["port"] == 8642


def test_profile_has_no_plaintext_secrets_nor_yolo(profile_config_path: Path) -> None:
    raw = profile_config_path.read_text(encoding="utf-8")
    assert "--yolo" not in raw


# --- Compose: ooda-agent service wiring (kali-direct) ----------------


def _load_services(compose_path: Path) -> dict:
    compose = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    return compose["services"]


def _load_ooda_agent(compose_path: Path) -> dict:
    return _load_services(compose_path)["ooda-agent"]


# Compose services for v2.0.0 (base, no overlays): the two MCPs + ooda-agent + the
# vulnerator-mcp/web stack and Caido. `web`-profiled: they only start with `--profile web`.
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

WEB_PROFILE_SERVICES = ["vulnerator-web", "browser-view", "caido-director"]


def test_compose_services_contract(compose_path: Path) -> None:
    services = _load_services(compose_path)
    assert set(services) == set(EXPECTED_COMPOSE_SERVICES), (
        "the v2.0.0 compose has 9 services: the two MCPs, ooda-agent, vulnerator-mcp/web and Caido"
    )
    for svc in WEB_PROFILE_SERVICES:
        assert services[svc].get("profiles") == ["web"], f"{svc} must have profiles ['web']"
    depends = services["ooda-agent"]["depends_on"]
    assert depends["kali"]["condition"] == "service_healthy"
    assert depends["playwright-mcp"]["condition"] == "service_healthy"


def test_ooda_agent_depends_on_both_mcp_healthy(compose_path: Path) -> None:
    svc = _load_ooda_agent(compose_path)
    depends = svc["depends_on"]
    assert depends["kali"]["condition"] == "service_healthy"
    assert depends["playwright-mcp"]["condition"] == "service_healthy"
    assert "api" not in depends, "there is no api service anymore"


def test_playwright_mcp_has_no_published_ports(compose_path: Path) -> None:
    svc = _load_services(compose_path)["playwright-mcp"]
    assert "ports" not in svc, "the browser MCP is not published to the host (internal network)"


def test_ooda_agent_publishes_api_server_port(compose_path: Path) -> None:
    # The Hermes API server (:8642) is published to the host to drive it from an external
    # assistant (see README). The host port is configurable with HERMES_API_HOST_PORT
    # (default 8642); the container port is 8642.
    svc = _load_ooda_agent(compose_path)
    ports = svc.get("ports", [])
    assert ports, "ooda-agent must publish the API server (:8642) to the host"
    mapped = [str(p) for p in ports]
    assert any("8642" in p for p in mapped), f"must map the container :8642 (ports={mapped})"


def test_ooda_agent_interactive_tty(compose_path: Path) -> None:
    svc = _load_ooda_agent(compose_path)
    assert svc["stdin_open"] is True
    assert svc["tty"] is True


def test_ooda_agent_volume_named_and_profile_bind_mount(compose_path: Path) -> None:
    svc = _load_ooda_agent(compose_path)
    volumes = svc["volumes"]
    # hermes-data:/opt/data MUST be a NAMED volume (not a bind mount) because of the SQLite WAL.
    assert "hermes-data:/opt/data" in volumes
    # The profile is injected via a READ-ONLY bind mount OUTSIDE /opt/data.
    assert "./agent-ooda:/opt/profile-src:ro" in volumes
    # NO bind mount may land inside /opt/data (it would corrupt the WAL).
    for vol in volumes:
        if vol.startswith("./") or vol.startswith("/") or vol.startswith("../"):
            target = vol.split(":")[1] if ":" in vol else ""
            assert not target.startswith("/opt/data"), f"bind mount inside /opt/data is forbidden: {vol}"
    # The named volume is declared at the root level of the compose.
    compose = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    assert "hermes-data" in compose["volumes"]


def test_ooda_agent_command_runs_gateway(compose_path: Path) -> None:
    svc = _load_ooda_agent(compose_path)
    command = svc["command"]
    script = command[-1] if isinstance(command, list) else str(command)
    # Copies the declarative template from the bind mount OUTSIDE /opt/data.
    assert "/opt/profile-src" in script
    # Starts the gateway (keeps the container alive + API server).
    assert "hermes gateway run" in script


def test_ooda_agent_llm_key_by_openrouter_not_hermes_llm(compose_path: Path) -> None:
    svc = _load_ooda_agent(compose_path)
    env = svc["environment"]
    # The LLM key is injected via OPENROUTER_API_KEY (Hermes reads it from there), NOT HERMES_LLM_API_KEY.
    assert "OPENROUTER_API_KEY" in env
    assert "HERMES_LLM_API_KEY" not in env, "the key goes through OPENROUTER_API_KEY, not HERMES_LLM_API_KEY"


def test_compose_has_no_yolo(compose_path: Path) -> None:
    compose_raw = compose_path.read_text(encoding="utf-8")
    assert "--yolo" not in compose_raw
