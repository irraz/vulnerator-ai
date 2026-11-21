#!/usr/bin/env python3
"""Smoke test del worktree de vulnerator-ai (contratos, tools, mapa, imports y tests).

Es un comprobador de andar por casa, no un test de producto: valida que el cableado
declarativo (config.yaml + docker-compose.yml), la superficie real de tools (por AST,
SIN importar los servidores), los anexos de ARCHITECTURE_MAP.md y la pureza SDK-free de
los modulos de logica sigan siendo lo que el mapa dice.

Uso:
    python3 scripts/smoke.py            # --quick (estatico + tests)
    python3 scripts/smoke.py --check    # solo contratos/tools/mapa/imports (alias de --static)
    python3 scripts/smoke.py --static   # solo contratos/tools/mapa/imports
    python3 scripts/smoke.py --tests    # solo las suites en subproceso
    python3 scripts/smoke.py --quick    # estatico + tests (gate rapido)

Disciplina:
  - NUNCA importa docker/kali/kali_mcp_server.py ni docker/mcp/vulnerator_mcp_server.py:
    las tools se leen con `ast` (decoradores @mcp.tool y constantes *_TOOL_NAME).
  - NUNCA usa --import-mode=importlib.
  - Los subprocesos de test corren con `env -u PYTHONPATH` y cwd=raiz.
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

GREEN, RED, WARN = "✅", "❌", "⚠️"

# Modulos de LOGICA PURA que no deben depender del SDK `mcp` (se importan de verdad).
SDK_FREE_IMPORT = [
    ROOT / "docker" / "mcp" / "mcp_tool_logic.py",
    ROOT / "docker" / "kali" / "scope_guard.py",
    ROOT / "docker" / "kali" / "tool_streaming.py",
    ROOT / "docker" / "kali" / "finding_store.py",
]

# Las suites y las dependencias que cada una necesita en el interprete de test.
# `scripts/tests` la anade la rama feat/base-linters; si aun no existe en esta rama
# se reporta con ⚠️ (una suite ausente no es una suite en rojo).
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
    ("scripts/tests", ["pytest"]),
]

EXPECTED_MCP_SERVERS = ["kali", "playwright"]
EXPECTED_TOOLSETS = ["kali", "playwright", "todo", "kanban"]
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
    """Acumulador de secciones con conteo de fallos y avisos."""

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


# --------------------------------------------------------------------------- utils


def ast_tool_decorations(path: Path) -> list[tuple[str, int]]:
    """Devuelve [(nombre, linea)] de las funciones decoradas con @mcp.tool(...).

    Solo AST: el fichero NO se importa. La linea es la del `def` (la del decorador es
    la inmediatamente anterior en este repo).
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
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


def tool_name_constants(path: Path) -> list[tuple[str, str]]:
    """Constante *_TOOL_NAME = "nombre" (mismo source of truth que los decoradores)."""
    src = path.read_text(encoding="utf-8")
    return re.findall(
        r'^([A-Z][A-Z0-9_]*_TOOL_NAME)\s*=\s*["\']([^"\']+)["\']', src, re.M
    )


def module_imports_mcp(path: Path) -> bool:
    """True si el modulo importa el SDK `mcp` (por AST, sin importarlo)."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
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
    """Localiza el binario de uv (env UV_BIN > PATH > ruta fijada del entorno)."""
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
    """Entorno del subproceso SIN PYTHONPATH (contamina con mcp 2.3.0)."""
    return {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}


# --------------------------------------------------------------------------- contratos


def check_contratos(rep: Report) -> None:
    import yaml

    section = "contratos"

    if not CONFIG.exists() or not COMPOSE.exists():
        rep.bad(
            section,
            f"faltan ficheros: config={CONFIG.exists()} compose={COMPOSE.exists()}",
        )
        return

    cfg = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))

    # --- config.yaml: los dos unicos MCP y sus URLs -------------------------
    servers = list((cfg.get("mcp_servers") or {}).keys())
    if servers == EXPECTED_MCP_SERVERS:
        rep.ok(section, f"config.yaml mcp_servers = {servers}")
    else:
        rep.bad(
            section,
            f"config.yaml mcp_servers = {servers} (esperado {EXPECTED_MCP_SERVERS})",
        )

    kali_cfg = (cfg.get("mcp_servers") or {}).get("kali") or {}
    if kali_cfg.get("url") == "http://kali:8900":
        rep.ok(section, "config.yaml kali.url = http://kali:8900")
    else:
        rep.bad(section, f"config.yaml kali.url = {kali_cfg.get('url')!r}")

    pw_cfg = (cfg.get("mcp_servers") or {}).get("playwright") or {}
    if pw_cfg.get("url") == "http://playwright-mcp:8931/mcp":
        rep.ok(section, "config.yaml playwright.url = http://playwright-mcp:8931/mcp")
    else:
        rep.bad(section, f"config.yaml playwright.url = {pw_cfg.get('url')!r}")

    # Sin tools.include: el servidor es la source of truth.
    kali_tools_cfg = kali_cfg.get("tools") or {}
    if "include" not in kali_tools_cfg:
        rep.ok(
            section,
            "config.yaml kali.tools sin 'include' (sin whitelist: el servidor manda)",
        )
    else:
        rep.bad(section, "config.yaml kali.tools.include presente (debe estar ausente)")

    if cfg.get("toolsets") == EXPECTED_TOOLSETS:
        rep.ok(section, f"config.yaml toolsets = {EXPECTED_TOOLSETS}")
    else:
        rep.bad(section, f"config.yaml toolsets = {cfg.get('toolsets')!r}")

    api = (cfg.get("platforms") or {}).get("api_server") or {}
    if api.get("enabled") is True and api.get("port") == 8642:
        rep.ok(section, "config.yaml platforms.api_server enabled=True port=8642")
    else:
        rep.bad(section, f"config.yaml platforms.api_server = {api!r}")

    if (cfg.get("model") or {}).get("default") == "mistralai/mistral-large-4-0":
        rep.ok(section, "config.yaml model.default = mistralai/mistral-large-4-0")
    else:
        rep.bad(
            section,
            f"config.yaml model.default = {(cfg.get('model') or {}).get('default')!r}",
        )

    config_raw = CONFIG.read_text(encoding="utf-8")
    if "--yolo" not in config_raw:
        rep.ok(section, "config.yaml sin '--yolo'")
    else:
        rep.bad(section, "config.yaml contiene '--yolo' (prohibido)")

    # --- docker-compose.yml: 9 servicios, 4 volumenes, profiles, depends ---
    services = compose.get("services") or {}
    volumes = list((compose.get("volumes") or {}).keys())

    if len(services) == 9 and sorted(services) == sorted(EXPECTED_COMPOSE_SERVICES):
        rep.ok(section, f"compose services = 9 ({', '.join(sorted(services))})")
    else:
        rep.bad(section, f"compose services = {sorted(services)}")

    if sorted(volumes) == sorted(EXPECTED_VOLUMES):
        rep.ok(section, f"compose volumes = {sorted(volumes)}")
    else:
        rep.bad(section, f"compose volumes = {volumes}")

    web_profile = sorted(
        name for name, svc in services.items() if "web" in (svc.get("profiles") or [])
    )
    if web_profile == sorted(EXPECTED_WEB_PROFILE):
        rep.ok(section, f"compose profile 'web' = {sorted(EXPECTED_WEB_PROFILE)}")
    else:
        rep.bad(section, f"compose profile 'web' = {web_profile}")

    ooda = services.get("ooda-agent") or {}
    depends = ooda.get("depends_on") or {}
    if (
        isinstance(depends, dict)
        and depends.get("kali", {}).get("condition") == "service_healthy"
        and depends.get("playwright-mcp", {}).get("condition") == "service_healthy"
    ):
        rep.ok(
            section,
            "compose ooda-agent depends_on kali+playwright-mcp (service_healthy)",
        )
    else:
        rep.bad(section, f"compose ooda-agent depends_on = {depends!r}")

    pw_svc = services.get("playwright-mcp") or {}
    if "ports" not in pw_svc:
        rep.ok(section, "compose playwright-mcp sin ports (red interna)")
    else:
        rep.bad(section, "compose playwright-mcp publica ports")

    ooda_ports = [str(p) for p in (ooda.get("ports") or [])]
    if any("8642" in p for p in ooda_ports):
        rep.ok(section, f"compose ooda-agent publica 8642 ({ooda_ports})")
    else:
        rep.bad(section, f"compose ooda-agent no publica 8642 ({ooda_ports})")

    compose_raw = COMPOSE.read_text(encoding="utf-8")
    if "--yolo" not in compose_raw:
        rep.ok(section, "compose sin '--yolo'")
    else:
        rep.bad(section, "compose contiene '--yolo' (prohibido)")


# --------------------------------------------------------------------------- tools


def check_tools(rep: Report) -> None:
    section = "tools"

    if not KALI_SERVER.exists() or not VULN_SERVER.exists():
        rep.bad(section, "faltan los servidores MCP")
        return

    kali_tools = ast_tool_decorations(KALI_SERVER)
    vuln_tools = ast_tool_decorations(VULN_SERVER)
    kali_consts = tool_name_constants(KALI_SERVER)

    if len(kali_tools) == 21:
        rep.ok(
            section,
            f"kali_mcp_server.py: 21 @mcp.tool por AST (lineas {[l for _, l in kali_tools]})",
        )
    else:
        rep.bad(
            section,
            f"kali_mcp_server.py: {len(kali_tools)} @mcp.tool por AST (esperadas 21)",
        )

    # 20 constantes *_TOOL_NAME: cubren todas las tools menos `server_info`, que usa
    # el decorador plano @mcp.tool() (sin name=) y toma el nombre de la funcion.
    tool_names = {n for n, _ in kali_tools}
    const_names = {n for _, n in kali_consts}
    if const_names == tool_names - {"server_info"}:
        rep.ok(
            section,
            "kali_mcp_server.py: 20 constantes *_TOOL_NAME cubren las 20 tools con name=",
        )
    else:
        rep.bad(
            section,
            f"kali_mcp_server.py: *_TOOL_NAME no cubren las tools (falta={sorted(tool_names - {'server_info'} - const_names)} "
            f"sobra={sorted(const_names - tool_names)})",
        )

    if len(vuln_tools) == 6:
        rep.ok(
            section,
            f"vulnerator_mcp_server.py: 6 @mcp.tool por AST ({[n for n, _ in vuln_tools]})",
        )
    else:
        rep.bad(
            section,
            f"vulnerator_mcp_server.py: {len(vuln_tools)} @mcp.tool por AST (esperadas 6)",
        )

    # Garantia: los servidores NO se importaron para leer las tools.
    leaked = [
        m for m in ("kali_mcp_server", "vulnerator_mcp_server") if m in sys.modules
    ]
    if not leaked:
        rep.ok(
            section, "servidores leidos solo por AST (no importados en este proceso)"
        )
    else:
        rep.bad(section, f"los servidores se importaron: {leaked}")


# --------------------------------------------------------------------------- mapa


ANNEX_A_ROW = re.compile(r"^\|\s*`([a-z_]+)`\s*\|\s*`([^`:]+):(\d+)`\s*\|\s*$")
ANNEX_B_ROW = re.compile(r"^\|\s*`([A-Za-z0-9._-]+)`\s*\|\s*`([^`:]+):(\d+)`\s*\|\s*$")


def _annex_tables(
    text: str,
) -> tuple[list[tuple[str, str, int]], list[tuple[str, str, int]]]:
    """Devuelve (filas Anexo A, filas Anexo B) como (clave, ruta, linea)."""
    lines = text.splitlines()

    def section(start_marker: str, end_marker: str) -> list[str]:
        try:
            i = next(n for n, l in enumerate(lines) if l.startswith(start_marker))
        except StopIteration:
            return []
        j = len(lines)
        for n in range(i + 1, len(lines)):
            if lines[n].startswith(end_marker):
                j = n
                break
        return lines[i:j]

    a_rows: list[tuple[str, str, int]] = []
    for line in section("## 11.", "## 12."):
        m = ANNEX_A_ROW.match(line.strip())
        if m:
            a_rows.append((m.group(1), m.group(2), int(m.group(3))))

    b_rows: list[tuple[str, str, int]] = []
    for line in section("## 12.", "## "):
        m = ANNEX_B_ROW.match(line.strip())
        if m:
            b_rows.append((m.group(1), m.group(2), int(m.group(3))))

    return a_rows, b_rows


def check_mapa(rep: Report) -> None:
    import yaml

    section = "mapa"

    if not MAP.exists():
        rep.bad(section, f"falta {MAP.relative_to(ROOT)}")
        return

    text = MAP.read_text(encoding="utf-8")
    a_rows, b_rows = _annex_tables(text)

    kali_ast = dict(ast_tool_decorations(KALI_SERVER))
    vuln_ast = dict(ast_tool_decorations(VULN_SERVER))

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

    if set(annex_kali) == set(kali_ast):
        bad_lines = [n for n, (p, l) in annex_kali.items() if kali_ast[n] != l]
        if not bad_lines:
            rep.ok(
                section,
                f"Anexo A: {len(annex_kali)} tools kali coinciden con AST (nombre+linea)",
            )
        else:
            rep.bad(section, f"Anexo A: linea erronea en {bad_lines}")
    else:
        missing = sorted(set(kali_ast) - set(annex_kali))
        extra = sorted(set(annex_kali) - set(kali_ast))
        rep.bad(section, f"Anexo A kali: falta={missing} sobra={extra}")

    if set(annex_vuln) == set(vuln_ast):
        bad_lines = [n for n, (p, l) in annex_vuln.items() if vuln_ast[n] != l]
        if not bad_lines:
            rep.ok(
                section,
                f"Anexo A: {len(annex_vuln)} tools vulnerator-mcp coinciden con AST (nombre+linea)",
            )
        else:
            rep.bad(section, f"Anexo A: linea erronea en {bad_lines}")
    else:
        missing = sorted(set(vuln_ast) - set(annex_vuln))
        extra = sorted(set(annex_vuln) - set(vuln_ast))
        rep.bad(section, f"Anexo A vulnerator-mcp: falta={missing} sobra={extra}")

    # Anexo B: servicios y volumenes contra el compose real.
    compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    services = compose.get("services") or {}
    volumes = list((compose.get("volumes") or {}).keys())
    compose_lines = COMPOSE.read_text(encoding="utf-8").splitlines()

    annex_services = {k: (p, l) for k, p, l in b_rows if k in services}
    annex_volumes = {k: (p, l) for k, p, l in b_rows if k in volumes}

    if set(annex_services) == set(services):
        bad = [
            k for k, (p, l) in annex_services.items() if k not in compose_lines[l - 1]
        ]
        if not bad:
            rep.ok(
                section,
                f"Anexo B: {len(annex_services)} servicios coinciden con compose (nombre+linea)",
            )
        else:
            rep.bad(section, f"Anexo B: linea no contiene el servicio {bad}")
    else:
        falta = sorted(set(services) - set(annex_services))
        sobra = sorted(set(annex_services) - set(services))
        rep.bad(section, f"Anexo B servicios: falta={falta} sobra={sobra}")

    if set(annex_volumes) == set(volumes):
        bad = [
            k for k, (p, l) in annex_volumes.items() if k not in compose_lines[l - 1]
        ]
        if not bad:
            rep.ok(
                section,
                f"Anexo B: {len(annex_volumes)} volumenes coinciden con compose (nombre+linea)",
            )
        else:
            rep.bad(section, f"Anexo B: linea no contiene el volumen {bad}")
    else:
        falta = sorted(set(volumes) - set(annex_volumes))
        sobra = sorted(set(annex_volumes) - set(volumes))
        rep.bad(section, f"Anexo B volumenes: falta={falta} sobra={sobra}")

    # Todas las rutas citadas en los anexos deben existir.
    broken = []
    for _key, path, _line in a_rows + b_rows:
        if not (ROOT / path).exists():
            broken.append(path)
    if not broken:
        rep.ok(section, "Anexo A/B: todas las rutas citadas existen (test -e)")
    else:
        rep.bad(section, f"Anexo A/B: rutas rotas {sorted(set(broken))}")

    if "scripts/smoke.py" in text:
        rep.ok(section, "el mapa enlaza scripts/smoke.py")
    else:
        rep.bad(section, "el mapa no enlaza scripts/smoke.py")


# --------------------------------------------------------------------------- imports


def check_imports(rep: Report) -> None:
    section = "imports"

    # 1) Unico punto que puede importar el SDK: los dos planes de control.
    offenders = []
    for path in sorted((ROOT / "docker").rglob("*.py")):
        if path in (KALI_SERVER, VULN_SERVER):
            continue
        if module_imports_mcp(path):
            offenders.append(str(path.relative_to(ROOT)))
    if not offenders:
        rep.ok(
            section,
            "solo kali_mcp_server.py y vulnerator_mcp_server.py importan el SDK 'mcp'",
        )
    else:
        rep.bad(
            section, f"modulos que importan 'mcp' fuera de los servidores: {offenders}"
        )

    # 2) Los modulos de logica pura se importan de verdad, sin el SDK y sin PYTHONPATH.
    missing = [str(p.relative_to(ROOT)) for p in SDK_FREE_IMPORT if not p.exists()]
    if missing:
        rep.bad(section, f"faltan modulos SDK-free: {missing}")
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
            "mcp_tool_logic/scope_guard/tool_streaming/finding_store importan sin el SDK 'mcp'",
        )
    else:
        rep.bad(section, f"import SDK-free fallo: {proc.stderr.strip()[:300]}")


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
        # Sin uv (p. ej. un CI con requirements-dev.txt ya instalado): pytest directo.
        cmd = [sys.executable, "-m", "pytest", suite, "-p", "no:cacheprovider", "-q"]
    proc = subprocess.run(
        cmd, cwd=str(ROOT), env=clean_env(), capture_output=True, text=True
    )
    output = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode, _parse_pytest_summary(output), output


def check_tests(rep: Report) -> None:
    section = "tests"
    uv = find_uv()
    if uv is None:
        rep.warn(
            section,
            "uv no encontrado: se usa pytest directo (requiere requirements-dev.txt)",
        )
    else:
        print(f"[{section}] uv = {uv}")
    any_failed = False
    ran = 0
    absent = 0
    for suite, deps in SUITES:
        if not (ROOT / suite).is_dir():
            absent += 1
            rep.warn(
                section, f"{suite}: no existe en esta rama (la anade feat/base-linters)"
            )
            continue
        ran += 1
        rc, counts, output = run_suite(suite, deps, uv)
        parts = [
            f"{counts[k]} {k}"
            for k in ("passed", "failed", "skipped", "errors")
            if counts[k]
        ]
        summary = ", ".join(parts) if parts else "sin recuento"
        if rc == 0:
            rep.ok(section, f"{suite}: {summary} (exit 0)")
        elif rc == 1:
            any_failed = True
            rep.bad(section, f"{suite}: {summary} (exit 1)")
        elif rc == 2:
            any_failed = True
            rep.bad(section, f"{suite}: error de coleccion ({summary}, exit 2)")
        elif rc == 5:
            rep.warn(section, f"{suite}: no se recolectaron tests (exit 5)")
        else:
            any_failed = True
            rep.bad(section, f"{suite}: exit {rc} ({summary})")

        # En fallo, volcar el short test summary para no ocultar nada.
        if rc not in (0, 5):
            tail = [line for line in output.splitlines() if line.strip()][-12:]
            for line in tail:
                print(f"[{section}]     {line}")

    if any_failed:
        rep.warn(
            section,
            "hay suites en rojo (en esta rama agent-ooda/tests tiene 4 tests declarativos desactualizados)",
        )
    elif absent:
        rep.ok(section, f"{ran} suites pasan; {absent} suite(s) ausentes en esta rama")
    else:
        rep.ok(section, f"las {ran} suites pasan")


# --------------------------------------------------------------------------- main


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Smoke test del worktree de vulnerator-ai"
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--check",
        action="store_true",
        help="alias de --static (contratos/tools/mapa/imports)",
    )
    group.add_argument(
        "--static", action="store_true", help="contratos + tools + mapa + imports"
    )
    group.add_argument("--tests", action="store_true", help="las suites en subproceso")
    group.add_argument(
        "--quick", action="store_true", help="estatico + tests (gate rapido)"
    )
    args = parser.parse_args()

    # Sin flags = gate rapido (estatico + tests).
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
    print(f"vulnerator-ai smoke — raiz: {ROOT}")

    if do_static:
        check_contratos(rep)
        check_tools(rep)
        check_mapa(rep)
        check_imports(rep)
        print(
            f"[check] resultado: {GREEN if rep.failures == 0 else RED} "
            f"fallos={rep.failures} avisos={rep.warnings}"
        )

    if do_tests:
        before = rep.failures
        check_tests(rep)
        print(
            f"[tests] resultado: {GREEN if rep.failures == before else RED} "
            f"fallos acumulados={rep.failures} avisos={rep.warnings}"
        )

    return 1 if rep.failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
