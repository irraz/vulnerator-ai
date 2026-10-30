"""Public contract of the kali-mcp plugin mechanism (PURE STDLIB, NO ``mcp``).

It is the face of the contract seen by plugin authors and shared by the loader
(``plugin_loader``) and —by text inspection— the skills ``for`` of the compose. It lives in
a separate module that uses ONLY the standard library so it can be covered by unit tests in
the dev venv, where the ``mcp`` SDK is not installed (just like ``shell_exec`` /
``collector_runner`` / ``scope_guard``).

What it exposes:
  - ``SUPPORTED_PLUGIN_API`` / ``DISABLED_SUFFIX`` / ``PLUGIN_DIR_NAME_RE``: contract
    constants. ``DISABLED_SUFFIX`` is the SINGLE source of the disabled suffix in the
    Python code (NIT-6): loader and compose shell share it.
  - ``PluginRecord`` / ``PluginLoadReport``: types of the report that ``server_info`` reads.
  - ``PluginContext``: the handle with fixed signatures (``PLUGIN_API=1``) that the plugin
    receives in its ``register(ctx)``. It detects collisions BEFORE registering a tool and
    validates that the skill does not escape the plugin's directory (MEDIUM-4). It is
    declarative: ``needs_volume`` does NOT mount or enable anything, it only annotates for
    ``server_info``.

This module does NOT import ``mcp``: ``PluginContext`` delegates to the ``mcp`` object it
receives (real FastMCP in the image, a double in the tests).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any

# Version of the contract that this core supports. A plugin declares its ``PLUGIN_API`` and
# the loader requires exact equality (phase 'api'); that way a contract break fails cleanly
# instead of loading an incompatible plugin halfway.
SUPPORTED_PLUGIN_API = 1

# Suffix that marks a plugin directory as DISABLED. SINGLE SOURCE (NIT-6): the loader uses
# it to ignore the dir and the compose ``for`` compares it by inspection.
DISABLED_SUFFIX = ".disabled"

# Allowed plugin directory name (MEDIUM-4): only alphanumerics and ``._-`` to avoid a weird
# name sneaking in as a module or breaking the ``sys.path`` insert.
PLUGIN_DIR_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")

# Version of the ``PluginContext`` contract (fixed signatures). Exposed as a class and
# instance attribute so a plugin can assert it if it wants.
PLUGIN_API = 1

# Common prefix of the plugin subsystem logs (loader and context).
_LOG_PREFIX = "[kali-mcp][plugins]"


@dataclass
class PluginRecord:
    """Per-discovered-plugin result, for the report and ``server_info``.

    ``phase`` describes HOW FAR it got: ``loaded`` (ok), ``degraded`` (loaded but with
    collisions) or the phase where it failed (``name``/``import``/``api``/``register-missing``/
    ``register``). ``error`` stores ONLY ``str(exc)`` (a single line, without paths); the full
    traceback goes to stdout/stderr, not to the report.
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
    """Aggregate report of a ``load_plugins`` pass (``server_info`` reads it)."""

    plugins: list[PluginRecord] = field(default_factory=list)

    def add(self, record: PluginRecord) -> None:
        self.plugins.append(record)


class PluginContext:
    """Handle the plugin receives in ``register(ctx)``. Fixed signatures: ``PLUGIN_API=1``.

    It is the only point through which a plugin touches the server: it registers tools (with
    collision detection), declares ONE skill (validated against path escapes) and annotates
    the volumes it needs (declarative). It does not run mount effects or enable anything on
    its own.
    """

    PLUGIN_API = PLUGIN_API

    def __init__(self, mcp: Any, plugin_dir: str) -> None:
        self._mcp = mcp
        self._plugin_dir = os.path.abspath(plugin_dir)
        self.PLUGIN_API = PLUGIN_API
        # Annotations collected by the loader after ``register(ctx)``.
        self.tools: list[str] = []
        self.collisions: list[str] = []
        self.volumes: list[str] = []
        # Validated path of the plugin's (single) skill. A DIFFERENT attribute from the
        # ``skill()`` method so as not to shadow it; the loader reads it as ``ctx.skill_path``.
        self.skill_path: str | None = None

    def _existing_tool_names(self) -> set[str]:
        """Names of tools already registered via FastMCP's internal API.

        MEDIUM-2: if ``mcp._tool_manager.list_tools()`` does not exist or raises, the
        exception is PROPAGATED so that the registration FAILS instead of delegating blindly
        (a collision cannot be detected without the reliable list of names).
        """
        tool_manager = self._mcp._tool_manager
        tools = tool_manager.list_tools()
        return {t.name for t in tools}

    def tool(self, *args: Any, **kwargs: Any):
        """Tool decorator with COLLISION DETECTION prior to delegating.

        It resolves the target name (kwarg ``name=`` or ``fn.__name__``) and queries the
        existing names. If it already exists -> it does NOT delegate, records the collision
        and returns the function untouched. If it does not exist -> it delegates literally to
        ``mcp.tool(*a, **k)`` and records the registered name. MEDIUM-2: if the list of names
        cannot be obtained, the registration FAILS (``_existing_tool_names`` propagates).
        """

        def _decorator(fn: Any) -> Any:
            name = kwargs.get("name") or getattr(fn, "__name__", None)
            existing = self._existing_tool_names()
            if name in existing:
                # Collision: the existing tool is not overwritten (add_tool would be a silent
                # no-op in FastMCP, but here it is explicitly recorded as a collision -> degraded).
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
        """Declares the plugin's SINGLE skill (path relative to the plugin dir).

        MEDIUM-4: it validates with ``os.path.realpath`` that the resolved path stays UNDER
        ``plugin_dir``; if it escapes -> a NON-fatal warning and it is NOT annotated. A second
        call is a contract error (at most one skill per plugin): it is logged and ignored.
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
        """Declares (only annotates) that the plugin needs a volume. Mounts NOTHING."""
        self.volumes.append(name)

    def plugin_dir(self) -> str:
        """Absolute path of the plugin's directory. ALWAYS returns a path, exist or not."""
        return self._plugin_dir

    def vendor_dir(self) -> str:
        """Absolute path of ``<plugin_dir>/vendor``. ALWAYS returns a path, exist or not."""
        return os.path.join(self._plugin_dir, "vendor")
