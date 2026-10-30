"""kali-mcp plugin loader by DISCOVERY (PURE STDLIB, NO ``mcp``).

It enumerates the immediate subdirectories of ``plugins_root`` that contain ``plugin.py``,
imports them ISOLATED (each namespaced under ``vuln_plugin_<dir>``) and gives them a
``PluginContext`` so they register tools/skill/volumes. Each plugin is processed inside its
own ``try/except`` so a broken one does not take down the others or the server startup. The
result is stored in the module singleton ``LAST_REPORT`` (HIGH-1) so that ``server_info``
reads it reliably.

Compatibility identical to today: if ``plugins_root`` does not exist or is not a directory,
the report is EMPTY and the server is not touched.

This module uses ONLY the standard library (it does not import ``mcp``) so it can be covered
by tests in the dev venv; ``load_plugins`` receives the ``mcp`` object (real FastMCP or a
double).
"""

from __future__ import annotations

import importlib.util
import os
import sys
import traceback

from plugin_api import (
    DISABLED_SUFFIX,
    PLUGIN_DIR_NAME_RE,
    SUPPORTED_PLUGIN_API,
    PluginContext,
    PluginLoadReport,
    PluginRecord,
)

# Log prefix of the loading subsystem (full tracebacks to stdout/stderr).
_LOG_PREFIX = "[kali-mcp][plugins]"

# Module singleton with the LAST loading report. ``server_info`` reads it (HIGH-1). It
# starts empty so that, if ``load_plugins`` was never called, ``server_info`` sees zero
# plugins (compat identical to today).
LAST_REPORT = PluginLoadReport()


def _iter_plugin_dirs(plugins_root: str) -> list[tuple[str, str]]:
    """Returns ``(name, plugin_dir)`` of the candidates, in deterministic ALPHABETICAL order.

    It ignores: non-directories, hidden ones (``.`` prefix), dirs ending in
    ``DISABLED_SUFFIX`` and dirs without ``plugin.py``. It does NOT filter by name regex
    here: an invalid name but with ``plugin.py`` must be reported as a phase 'name' failure
    (MEDIUM-4), not skipped.
    """
    candidates: list[tuple[str, str]] = []
    for name in sorted(os.listdir(plugins_root)):
        if name.startswith("."):
            continue
        if name.endswith(DISABLED_SUFFIX):
            continue
        plugin_dir = os.path.join(plugins_root, name)
        if not os.path.isdir(plugin_dir):
            continue
        if not os.path.isfile(os.path.join(plugin_dir, "plugin.py")):
            continue
        candidates.append((name, plugin_dir))
    return candidates


def _load_one(mcp, name: str, plugin_dir: str) -> PluginRecord:
    """Loads a plugin ISOLATED applying the MEDIUM-3/NIT-8 micro-algorithm.

    Phases: 'name' (dir regex) -> 'import' (exec of the body, triggers the ``import
    <sibling>`` via the ``sys.path`` insert) -> 'api' (PLUGIN_API) -> 'register-missing'
    (callable absent) -> 'register' (``register(ctx)``). On a 'register' failure the
    already-mounted tools are ROLLED BACK (NIT-8) so as not to leave visible orphan tools.
    """
    # (phase name) The dir name must match the regex BEFORE touching sys.path/import.
    if not PLUGIN_DIR_NAME_RE.match(name):
        print(
            f"{_LOG_PREFIX} plugin '{name}' rechazado: nombre de directorio inválido",
            flush=True,
        )
        return PluginRecord(
            name=name,
            status="failed",
            phase="name",
            error="invalid plugin directory name",
        )

    plugin_py = os.path.join(plugin_dir, "plugin.py")
    mod_name = f"vuln_plugin_{name}"
    ctx = PluginContext(mcp, plugin_dir)

    # (a) sys.path insert BEFORE executing the body, so that ``import <sibling>`` inside
    # plugin.py resolves against the plugin's own directory (MEDIUM-3).
    sys.path.insert(0, plugin_dir)
    try:
        # (b) phase 'import': spec_from_file_location + exec_module runs the body and
        # triggers the sibling imports; its failure lands here.
        try:
            spec = importlib.util.spec_from_file_location(mod_name, plugin_py)
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
        except Exception as exc:  # noqa: BLE001 - isolated: a broken plugin does not take down the rest
            traceback.print_exc()
            return PluginRecord(name=name, status="failed", phase="import", error=str(exc))

        # (c) phase 'api': the plugin must declare a compatible PLUGIN_API (exact equality).
        plugin_api_version = getattr(module, "PLUGIN_API", None)
        if plugin_api_version != SUPPORTED_PLUGIN_API:
            msg = (
                f"PLUGIN_API {plugin_api_version!r} incompatible; "
                f"soportado {SUPPORTED_PLUGIN_API}"
            )
            print(f"{_LOG_PREFIX} plugin '{name}' rechazado: {msg}", flush=True)
            return PluginRecord(name=name, status="failed", phase="api", error=msg)

        # (d) phase 'register-missing': it must expose a callable ``register``.
        register = getattr(module, "register", None)
        if not callable(register):
            msg = "falta un callable register(ctx)"
            print(f"{_LOG_PREFIX} plugin '{name}' rechazado: {msg}", flush=True)
            return PluginRecord(
                name=name, status="failed", phase="register-missing", error=msg
            )

        # (e) phase 'register': run register(ctx). If it raises, NIT-8: roll back tools.
        try:
            register(ctx)
        except Exception as exc:  # noqa: BLE001 - isolated
            traceback.print_exc()
            for tool_name in ctx.tools:
                try:
                    mcp._tool_manager.remove_tool(tool_name)
                except Exception:  # noqa: BLE001 - best-effort rollback
                    traceback.print_exc()
            return PluginRecord(
                name=name, status="failed", phase="register", error=str(exc)
            )

        # (f) collect what was annotated; collisions -> degraded (loaded, but not all entered).
        if ctx.collisions:
            status, phase = "degraded", "register"
        else:
            status, phase = "loaded", "loaded"
        return PluginRecord(
            name=name,
            status=status,
            phase=phase,
            tools=list(ctx.tools),
            skill=ctx.skill_path,
            volumes=list(ctx.volumes),
            collisions=list(ctx.collisions),
        )
    finally:
        # (g) restore sys.path after each plugin (remove ONLY the inserted entry).
        try:
            sys.path.remove(plugin_dir)
        except ValueError:
            pass


def load_plugins(mcp, plugins_root: str) -> PluginLoadReport:
    """Discovers and loads the plugins under ``plugins_root``. Returns and publishes the report.

    If ``plugins_root`` does not exist or is not a directory -> EMPTY report (compat
    identical to today). Before returning, it assigns ``plugin_loader.LAST_REPORT = report``
    (HIGH-1).
    """
    global LAST_REPORT
    report = PluginLoadReport()

    if not plugins_root or not os.path.isdir(plugins_root):
        LAST_REPORT = report
        return report

    for name, plugin_dir in _iter_plugin_dirs(plugins_root):
        record = _load_one(mcp, name, plugin_dir)
        report.add(record)

    LAST_REPORT = report
    return report
