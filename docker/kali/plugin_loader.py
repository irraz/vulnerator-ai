"""Cargador por DESCUBRIMIENTO de plugins de kali-mcp (STDLIB PURA, SIN ``mcp``).

Enumera los subdirectorios inmediatos de ``plugins_root`` que contienen ``plugin.py``, los
importa AISLADOS (cada uno namespaced bajo ``vuln_plugin_<dir>``) y les da un
``PluginContext`` para que registren tools/skill/volúmenes. Cada plugin se procesa dentro
de su propio ``try/except`` para que uno roto no tumbe a los demás ni al arranque del
servidor. El resultado se guarda en el singleton de módulo ``LAST_REPORT`` (HIGH-1) para
que ``server_info`` lo lea de forma fiable.

Compatibilidad idéntica a hoy: si ``plugins_root`` no existe o no es un directorio, el
reporte es VACÍO y no se toca el servidor.

Este módulo usa SOLO la librería estándar (no importa ``mcp``) para cubrirse con tests en
el venv de dev; ``load_plugins`` recibe el objeto ``mcp`` (FastMCP real o un doble).
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

# Prefijo de logs del subsistema de carga (tracebacks completos a stdout/stderr).
_LOG_PREFIX = "[kali-mcp][plugins]"

# Singleton de módulo con el ÚLTIMO reporte de carga. ``server_info`` lo lee (HIGH-1).
# Arranca vacío para que, si nunca se llamó a ``load_plugins``, ``server_info`` vea cero
# plugins (compat idéntica a hoy).
LAST_REPORT = PluginLoadReport()


def _iter_plugin_dirs(plugins_root: str) -> list[tuple[str, str]]:
    """Devuelve ``(name, plugin_dir)`` de los candidatos, en orden ALFABÉTICO determinista.

    Ignora: no-directorios, ocultos (prefijo ``.``), dirs terminados en ``DISABLED_SUFFIX``
    y dirs sin ``plugin.py``. NO filtra por regex de nombre aquí: un nombre inválido pero
    con ``plugin.py`` debe reportarse como fallo de fase 'name' (MEDIUM-4), no omitirse.
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
    """Carga un plugin AISLADO aplicando el micro-algoritmo MEDIUM-3/NIT-8.

    Fases: 'name' (regex de dir) -> 'import' (exec del cuerpo, dispara los ``import
    <hermano>`` vía el ``sys.path`` insert) -> 'api' (PLUGIN_API) -> 'register-missing'
    (callable ausente) -> 'register' (``register(ctx)``). En fallo de 'register' se
    REVIERTEN las tools ya montadas (NIT-8) para no dejar tools huérfanas visibles.
    """
    # (fase name) El nombre de dir debe casar el regex ANTES de tocar sys.path/import.
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

    # (a) sys.path insert ANTES de ejecutar el cuerpo, para que ``import <hermano>`` dentro
    # de plugin.py resuelva contra el propio directorio del plugin (MEDIUM-3).
    sys.path.insert(0, plugin_dir)
    try:
        # (b) fase 'import': spec_from_file_location + exec_module ejecuta el cuerpo y
        # dispara los imports de hermanos; su fallo cae aquí.
        try:
            spec = importlib.util.spec_from_file_location(mod_name, plugin_py)
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
        except Exception as exc:  # noqa: BLE001 - aislado: un plugin roto no tumba al resto
            traceback.print_exc()
            return PluginRecord(name=name, status="failed", phase="import", error=str(exc))

        # (c) fase 'api': el plugin debe declarar un PLUGIN_API compatible (igualdad exacta).
        plugin_api_version = getattr(module, "PLUGIN_API", None)
        if plugin_api_version != SUPPORTED_PLUGIN_API:
            msg = (
                f"PLUGIN_API {plugin_api_version!r} incompatible; "
                f"soportado {SUPPORTED_PLUGIN_API}"
            )
            print(f"{_LOG_PREFIX} plugin '{name}' rechazado: {msg}", flush=True)
            return PluginRecord(name=name, status="failed", phase="api", error=msg)

        # (d) fase 'register-missing': debe exponer un ``register`` callable.
        register = getattr(module, "register", None)
        if not callable(register):
            msg = "falta un callable register(ctx)"
            print(f"{_LOG_PREFIX} plugin '{name}' rechazado: {msg}", flush=True)
            return PluginRecord(
                name=name, status="failed", phase="register-missing", error=msg
            )

        # (e) fase 'register': ejecutar register(ctx). Si lanza, NIT-8: revertir tools.
        try:
            register(ctx)
        except Exception as exc:  # noqa: BLE001 - aislado
            traceback.print_exc()
            for tool_name in ctx.tools:
                try:
                    mcp._tool_manager.remove_tool(tool_name)
                except Exception:  # noqa: BLE001 - best-effort de reversión
                    traceback.print_exc()
            return PluginRecord(
                name=name, status="failed", phase="register", error=str(exc)
            )

        # (f) recoger lo anotado; colisiones -> degraded (cargó, pero no todo entró).
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
        # (g) restaurar sys.path tras cada plugin (quitar SOLO la entrada insertada).
        try:
            sys.path.remove(plugin_dir)
        except ValueError:
            pass


def load_plugins(mcp, plugins_root: str) -> PluginLoadReport:
    """Descubre y carga los plugins bajo ``plugins_root``. Devuelve y publica el reporte.

    Si ``plugins_root`` no existe o no es un directorio -> reporte VACÍO (compat idéntica a
    hoy). Antes de devolver, asigna ``plugin_loader.LAST_REPORT = report`` (HIGH-1).
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
