"""Contrato público del mecanismo de plugins de kali-mcp (STDLIB PURA, SIN ``mcp``).

Es la cara del contrato que ven los autores de plugins y que comparten el cargador
(``plugin_loader``) y —por inspección de texto— el ``for`` de skills del compose. Vive en
un módulo aparte que usa SOLO la librería estándar para poder cubrirse con tests unitarios
en el venv de dev, donde el SDK ``mcp`` no está instalado (igual que ``shell_exec`` /
``collector_runner`` / ``scope_guard``).

Qué expone:
  - ``SUPPORTED_PLUGIN_API`` / ``DISABLED_SUFFIX`` / ``PLUGIN_DIR_NAME_RE``: constantes de
    contrato. ``DISABLED_SUFFIX`` es la ÚNICA fuente del sufijo de deshabilitado en el
    código Python (NIT-6): loader y shell del compose lo comparten.
  - ``PluginRecord`` / ``PluginLoadReport``: tipos del reporte que lee ``server_info``.
  - ``PluginContext``: el handle con firmas fijas (``PLUGIN_API=1``) que el plugin recibe
    en su ``register(ctx)``. Detecta colisiones ANTES de registrar una tool y valida que
    la skill no escape del directorio del plugin (MEDIUM-4). Es declarativo: ``needs_volume``
    NO monta ni habilita nada, solo anota para ``server_info``.

Este módulo NO importa ``mcp``: ``PluginContext`` delega en el objeto ``mcp`` que recibe
(FastMCP real en la imagen, un doble en los tests).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any

# Versión del contrato que este core soporta. Un plugin declara su ``PLUGIN_API`` y el
# loader exige igualdad exacta (fase 'api'); así una ruptura de contrato falla claro en
# lugar de cargar un plugin incompatible a medias.
SUPPORTED_PLUGIN_API = 1

# Sufijo que marca un directorio de plugin como DESHABILITADO. FUENTE ÚNICA (NIT-6): el
# loader lo usa para ignorar el dir y el ``for`` del compose lo compara por inspección.
DISABLED_SUFFIX = ".disabled"

# Nombre de directorio de plugin permitido (MEDIUM-4): solo alfanuméricos y ``._-`` para
# evitar que un nombre raro se cuele como módulo o rompa el ``sys.path`` insert.
PLUGIN_DIR_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")

# Versión del contrato de ``PluginContext`` (firmas fijas). Se expone como atributo de
# clase e instancia para que un plugin pueda afirmarla si quisiera.
PLUGIN_API = 1

# Prefijo común de los logs del subsistema de plugins (loader y contexto).
_LOG_PREFIX = "[kali-mcp][plugins]"


@dataclass
class PluginRecord:
    """Resultado por plugin descubierto, para el reporte y ``server_info``.

    ``phase`` describe HASTA DÓNDE llegó: ``loaded`` (ok), ``degraded`` (cargó pero con
    colisiones) o la fase donde falló (``name``/``import``/``api``/``register-missing``/
    ``register``). ``error`` guarda SOLO ``str(exc)`` (una línea, sin rutas); el traceback
    completo va a stdout/stderr, no al reporte.
    """

    name: str
    status: str  # "loaded" | "degraded" | "failed"
    phase: str
    tools: list[str] = field(default_factory=list)
    skill: str | None = None
    volumes: list[str] = field(default_factory=list)
    collisions: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class PluginLoadReport:
    """Reporte agregado de una pasada de ``load_plugins`` (lo lee ``server_info``)."""

    plugins: list[PluginRecord] = field(default_factory=list)

    def add(self, record: PluginRecord) -> None:
        self.plugins.append(record)


class PluginContext:
    """Handle que el plugin recibe en ``register(ctx)``. Firmas fijas: ``PLUGIN_API=1``.

    Es el único punto por el que un plugin toca el servidor: registra tools (con detección
    de colisión), declara UNA skill (validada contra escapes de ruta) y anota volúmenes que
    necesita (declarativo). No ejecuta efectos de montaje ni habilita nada por sí mismo.
    """

    PLUGIN_API = PLUGIN_API

    def __init__(self, mcp: Any, plugin_dir: str) -> None:
        self._mcp = mcp
        self._plugin_dir = os.path.abspath(plugin_dir)
        self.PLUGIN_API = PLUGIN_API
        # Anotaciones recogidas por el loader tras ``register(ctx)``.
        self.tools: list[str] = []
        self.collisions: list[str] = []
        self.volumes: list[str] = []
        # Ruta validada de la (única) skill del plugin. Atributo DISTINTO del método
        # ``skill()`` para no sombrearlo; el loader lo lee como ``ctx.skill_path``.
        self.skill_path: str | None = None

    def _existing_tool_names(self) -> set[str]:
        """Nombres de tool ya registradas vía la API interna de FastMCP.

        MEDIUM-2: si ``mcp._tool_manager.list_tools()`` no existe o lanza, se PROPAGA la
        excepción para que el registro FALLE en vez de delegar a ciegas (no se puede
        detectar colisión sin la lista fiable de nombres).
        """
        tool_manager = self._mcp._tool_manager
        tools = tool_manager.list_tools()
        return {t.name for t in tools}

    def tool(self, *args: Any, **kwargs: Any):
        """Decorador de tool con DETECCIÓN DE COLISIÓN previa a delegar.

        Resuelve el nombre objetivo (kwarg ``name=`` o ``fn.__name__``) y consulta los
        nombres existentes. Si ya existe -> NO delega, anota la colisión y devuelve la
        función intacta. Si no existe -> delega literalmente en ``mcp.tool(*a, **k)`` y
        anota el nombre registrado. MEDIUM-2: si no se puede obtener la lista de nombres,
        el registro FALLA (``_existing_tool_names`` propaga).
        """

        def _decorator(fn: Any) -> Any:
            name = kwargs.get("name") or getattr(fn, "__name__", None)
            existing = self._existing_tool_names()
            if name in existing:
                # Colisión: no se pisa la tool existente (add_tool sería un no-op silencioso
                # de FastMCP, pero aquí se anota explícitamente como colisión -> degraded).
                self.collisions.append(name)
                print(
                    f"{_LOG_PREFIX} collision: tool '{name}' ya existe; "
                    "el plugin NO la registra",
                    flush=True,
                )
                return fn
            decorated = self._mcp.tool(*args, **kwargs)(fn)
            self.tools.append(name)
            return decorated

        return _decorator

    def skill(self, path: str) -> None:
        """Declara la ÚNICA skill del plugin (ruta relativa al dir del plugin).

        MEDIUM-4: valida con ``os.path.realpath`` que la ruta resuelta queda BAJO
        ``plugin_dir``; si escapa -> warning NO fatal y NO se anota. Una segunda llamada es
        un error de contrato (máximo una skill por plugin): se loguea y se ignora.
        """
        if self.skill_path is not None:
            print(
                f"{_LOG_PREFIX} contract error: solo se admite UNA skill por plugin; "
                f"se ignora la skill adicional '{path}'",
                flush=True,
            )
            return
        resolved = os.path.realpath(os.path.join(self._plugin_dir, path))
        root = os.path.realpath(self._plugin_dir)
        if resolved != root and not resolved.startswith(root + os.sep):
            print(
                f"{_LOG_PREFIX} warning: la skill '{path}' escapa del directorio del "
                "plugin; se ignora",
                flush=True,
            )
            return
        self.skill_path = resolved

    def needs_volume(self, name: str) -> None:
        """Declara (solo anota) que el plugin necesita un volumen. NO monta nada."""
        self.volumes.append(name)

    def plugin_dir(self) -> str:
        """Ruta absoluta del directorio del plugin. SIEMPRE devuelve ruta, exista o no."""
        return self._plugin_dir

    def vendor_dir(self) -> str:
        """Ruta absoluta de ``<plugin_dir>/vendor``. SIEMPRE devuelve ruta, exista o no."""
        return os.path.join(self._plugin_dir, "vendor")
