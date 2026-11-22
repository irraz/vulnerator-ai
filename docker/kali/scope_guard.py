"""Scope-guard OPT-IN de `kali-mcp` (STDLIB PURA) — valida el destino antes de ejecutar.

DETERMINISTIC layer (code, not prompt) that validates the target of every offensive action of
``kali_run``/``kali_exec`` ANTES de ejecutarla. Es OPT-IN: sin un ``scope.json`` presente
y ``enabled: true``, el comportamiento actual no cambia en absoluto (passthrough). Cuando
is active it is FAIL-CLOSED: if the target is not allowed —or if Hermes does not declare
destinos— la tool falla con un error estructurado y NO ejecuta el comando.

Why a separate module, like ``shell_exec.py``/``finding_store.py``:
``kali_mcp_server.py`` imports ``mcp``/``anyio`` (not in the dev venv). This
mechanism uses ONLY the standard library (``os``/``json``/``ipaddress``/``urllib.parse``/
``re``), so its logic is covered by unit tests without the SDK. ZERO new dependencies
(ni YAML/pyyaml): el archivo de scope es ``scope.json`` y se parsea con ``json``.

Design (decisions agreed with the operator):
  - Activation ONLY if the file (``SCOPE_FILE``, default ``/scope/scope.json``) exists and
    contiene ``enabled: true``. ``SCOPE_ENFORCE=0`` es un kill-switch que fuerza desactivar.
    Env vars are ONLY boolean switches; the ONLY data source (allow/deny/
    ports) es el archivo.
  - HYBRID target extraction: Hermes declares ``targets`` (the gate's source of truth)
    and, additionally, best-effort parsing of the command as an EXTRA BELT that can only
    BLOCK obvious out-of-scope targets, NEVER approve on its own.
  - ESTRICTO: con scope activo y SIN ``targets`` declarados -> se bloquea (no se ejecuta).
  - v1 validation: IP against allow CIDRs (``ipaddress``); hostname by LITERAL match
    (SIN DNS; un sufijo NO coincide); puertos opcionales. deny tiene PRIORIDAD sobre allow.

File loading (I/O + parse) is separated from validation (pure logic over dicts)
so the decision can be tested with in-memory dicts without touching the filesystem.

Disciplina de seguridad: el ``command`` y los ``targets`` son DATO NO CONFIABLE. El
best-effort belt is deliberately conservative (see notes in ``evaluate``): it never
approves, it only tightens. A corrupt config with the guard triggering is a
fail-closed configuration failure (``ScopeError``), not a silent passthrough.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Optional, Union
from urllib.parse import urlsplit

# Canonical path of the scope file inside the Kali container (overridable via env).
DEFAULT_SCOPE_FILE = "/scope/scope.json"

# Objetos de red de la stdlib (IPv4/IPv6) devueltos por ``ipaddress.ip_network``.
_Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
_Address = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


class ScopeError(ValueError):
    """Invalid/corrupt scope config (fail-closed: with the guard active, nothing runs)."""


@dataclass
class Target:
    """Destino normalizado a partir de una entrada de ``targets`` o del comando.

    ``ip`` es un objeto ``ipaddress`` si ``host`` parsea como IP literal, o ``None`` si es
    a hostname. ``port`` is the explicit/inferred port, or ``None`` if absent.
    """

    raw: str
    host: str
    ip: Optional[_Address] = None
    port: Optional[int] = None


@dataclass
class ScopeConfig:
    """Already-compiled scope config (networks as objects, normalized hosts)."""

    enabled: bool
    allow_cidrs: list[_Network] = field(default_factory=list)
    allow_hosts: set[str] = field(default_factory=set)
    deny_cidrs: list[_Network] = field(default_factory=list)
    deny_hosts: set[str] = field(default_factory=set)
    ports: Optional[set[int]] = None


@dataclass
class ScopeDecision:
    """Veredicto del gate. ``enforced`` es True si el guard estaba activo."""

    allowed: bool
    violations: list[dict[str, Any]] = field(default_factory=list)
    enforced: bool = False


# ---------------------------------------------------------------- activation / loading


def is_enforcing(config: Optional[ScopeConfig]) -> bool:
    """True si el guard debe aplicar el gate.

    Centralized activation rule: ``config`` exists, is ``enabled``, and the kill-switch
    ``SCOPE_ENFORCE`` is not ``"0"``. This lets the operator disable the guard hot
    (``SCOPE_ENFORCE=0``) aunque el archivo diga ``enabled: true``, sin tocar el archivo.
    """
    if config is None or not config.enabled:
        return False
    if os.environ.get("SCOPE_ENFORCE", "").strip() == "0":
        return False
    return True


def load_scope(path: Optional[str] = None) -> Optional[ScopeConfig]:
    """Loads the scope file (I/O + parse ISOLATED from target validation).

    Lee ``path`` o, si no se pasa, ``SCOPE_FILE`` (default ``/scope/scope.json``).

      - Si el archivo NO existe -> devuelve ``None`` (sin gate; comportamiento actual).
      - Si existe -> lo parsea con ``json.loads`` y delega en ``parse_scope``.
      - If it exists but is unreadable/invalid JSON -> ``ScopeError`` (config fail-closed).
    """
    scope_path: str = path or os.environ.get("SCOPE_FILE") or DEFAULT_SCOPE_FILE
    if not os.path.isfile(scope_path):
        return None
    try:
        with open(scope_path, "r", encoding="utf-8") as handle:
            raw = handle.read()
        data = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise ScopeError(
            "scope file %r unreadable or invalid JSON: %s" % (scope_path, exc)
        ) from exc
    return parse_scope(data)


def _compile_entries(
    entries: Any, where: str
) -> tuple[list[_Network], set[str]]:
    """Compila una lista de ``{cidr: ...}``/``{host: ...}`` a (redes, hosts).

    PURE logic (no filesystem). Malformed input -> ``ScopeError`` (fail-closed of
    config): un CIDR no parseable o una entrada sin ``cidr``/``host`` detiene la carga en
    vez de ignorarse en silencio (una config corrupta con el guard activo no debe ejecutar).
    """
    cidrs: list[_Network] = []
    hosts: set[str] = set()
    if entries is None:
        return cidrs, hosts
    if not isinstance(entries, list):
        raise ScopeError("'%s' debe ser una lista de entradas {cidr}/{host}." % where)
    for entry in entries:
        if not isinstance(entry, dict):
            raise ScopeError(
                "'%s' contiene una entrada que no es objeto {cidr}/{host}: %r"
                % (where, entry)
            )
        if "cidr" in entry:
            value = entry["cidr"]
            if not isinstance(value, str) or not value.strip():
                raise ScopeError("'%s' has an empty or non-string 'cidr'." % where)
            try:
                cidrs.append(ipaddress.ip_network(value.strip(), strict=False))
            except ValueError as exc:
                raise ScopeError(
                    "'%s' has an invalid CIDR %r: %s" % (where, value, exc)
                ) from exc
        elif "host" in entry:
            value = entry["host"]
            if not isinstance(value, str) or not value.strip():
                raise ScopeError("'%s' has an empty or non-string 'host'." % where)
            hosts.add(value.strip())
        else:
            raise ScopeError(
                "'%s' tiene una entrada sin 'cidr' ni 'host': %r" % (where, entry)
            )
    return cidrs, hosts


def parse_scope(data: Any) -> ScopeConfig:
    """Validates and compiles a scope dict into ``ScopeConfig`` (PURE logic, testable).

    Rules (configuration fail-closed):
      - ``data`` es un objeto JSON (dict).
      - ``enabled`` es bool (default ``False`` si falta).
      - ``allow``/``deny`` son listas de ``{cidr}``/``{host}`` (compiladas con ``ipaddress``).
      - ``ports``, if present, is a list of integers (allowed ports). Empty list or
        ausente -> ``None`` (cualquier puerto permitido para un host permitido).
    """
    if not isinstance(data, dict):
        raise ScopeError("invalid scope: expected a JSON object at the root.")

    enabled = data.get("enabled", False)
    if not isinstance(enabled, bool):
        raise ScopeError("invalid scope: 'enabled' must be boolean.")

    allow_cidrs, allow_hosts = _compile_entries(data.get("allow"), "allow")
    deny_cidrs, deny_hosts = _compile_entries(data.get("deny"), "deny")

    ports_raw = data.get("ports")
    ports: Optional[set[int]] = None
    if ports_raw is not None:
        if not isinstance(ports_raw, list):
            raise ScopeError("invalid scope: 'ports' must be a list of integers.")
        compiled_ports: set[int] = set()
        for port in ports_raw:
            # bool is a subclass of int; explicitly excluded so True/False are not accepted.
            if isinstance(port, bool) or not isinstance(port, int) or not (0 <= port <= 65535):
                raise ScopeError(
                    "invalid scope: 'ports' contains a non-port value: %r" % (port,)
                )
            compiled_ports.add(port)
        if compiled_ports:
            ports = compiled_ports

    return ScopeConfig(
        enabled=enabled,
        allow_cidrs=allow_cidrs,
        allow_hosts=allow_hosts,
        deny_cidrs=deny_cidrs,
        deny_hosts=deny_hosts,
        ports=ports,
    )


# ---------------------------------------------------------------- target normalization


_SCHEME_DEFAULT_PORTS = {"http": 80, "https": 443}

# host:port sin esquema (host es dominio/IPv4; IPv6 se maneja con la forma [..]:port).
_HOSTPORT_RE = re.compile(r"^(?P<host>[^\s/:]+):(?P<port>\d{1,5})$")
_IPV6_HOSTPORT_RE = re.compile(r"^\[(?P<host>[0-9A-Fa-f:]+)\](?::(?P<port>\d{1,5}))?$")


def _as_ip(host: str) -> Optional[_Address]:
    """Devuelve el objeto IP si ``host`` parsea como IP literal, o ``None`` (hostname)."""
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def normalize_target(raw: str) -> Target:
    """Normaliza una entrada (IP/host/URL/host:port) a ``Target``. Pura y testeable.

    Acepta:
      - IP literal: ``"8.8.8.8"``, ``"::1"``.
      - Hostname: ``"juice-shop"`` (match LITERAL contra allow hosts).
      - URL: ``"http://juice-shop:3000/x"``, ``"https://10.0.0.5"`` (puerto del ``:port``
        explicit or inferred from the scheme only for the ``ports`` check).
      - host:port sin esquema: ``"10.0.0.5:8080"``, ``"juice-shop:3000"``, ``"[::1]:8080"``.
    """
    token = (raw or "").strip()
    host = token
    port: Optional[int] = None

    # URL con esquema (http/https/...): usar urlsplit para separar host/puerto.
    if "://" in token:
        parts = urlsplit(token)
        if parts.hostname:
            host = parts.hostname
            if parts.port is not None:
                port = parts.port
            elif parts.scheme in _SCHEME_DEFAULT_PORTS:
                port = _SCHEME_DEFAULT_PORTS[parts.scheme]
        return Target(raw=raw, host=host, ip=_as_ip(host), port=port)

    # IPv6 con/ sin puerto en forma [..]:port.
    m6 = _IPV6_HOSTPORT_RE.match(token)
    if m6:
        host = m6.group("host")
        if m6.group("port"):
            port = int(m6.group("port"))
        return Target(raw=raw, host=host, ip=_as_ip(host), port=port)

    # Direct literal IP (IPv4 or IPv6 without brackets): do not split on ':' (would break IPv6).
    direct_ip = _as_ip(token)
    if direct_ip is not None:
        return Target(raw=raw, host=token, ip=direct_ip, port=None)

    # host:port sin esquema (host no-IPv6).
    mhp = _HOSTPORT_RE.match(token)
    if mhp:
        host = mhp.group("host")
        port = int(mhp.group("port"))
        return Target(raw=raw, host=host, ip=_as_ip(host), port=port)

    # Hostname literal (o lo que quede): sin puerto.
    return Target(raw=raw, host=host, ip=None, port=port)


# Candidate IP/URL/host:port tokens in the command (best-effort belt, conservative).
_CMD_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_CMD_URL_RE = re.compile(r"\bhttps?://[^\s'\"]+", re.IGNORECASE)


def extract_targets_from_command(command: str) -> list[Target]:
    """BEST-EFFORT parsing of the command -> list of ``Target`` (possibly empty).

    EXTRA BELT (decision 3): its output is only used to BLOCK obvious targets outside
    de scope, NUNCA para aprobar. Deliberadamente conservador: extrae URLs ``http(s)://`` y
    tokens que parezcan IPv4 literales. No intenta un parser de shell completo (una IP
    ofuscada/construida por el comando puede no detectarse -> falso negativo; por eso la
    fuente de verdad es ``targets``, que Hermes DEBE declarar con scope activo).
    """
    if not isinstance(command, str) or not command:
        return []
    found: list[Target] = []
    seen: set[str] = set()

    for match in _CMD_URL_RE.findall(command):
        token = match.rstrip(".,;)")
        if token not in seen:
            seen.add(token)
            found.append(normalize_target(token))

    for match in _CMD_IPV4_RE.findall(command):
        if match in seen:
            continue
        # Only well-formed IPv4 (discards "1.2.3.4" that is not a valid IP, e.g. 999.*).
        ip = _as_ip(match)
        if ip is None:
            continue
        seen.add(match)
        found.append(Target(raw=match, host=match, ip=ip, port=None))

    return found


# ---------------------------------------------------------------- gate decision


def _in_cidrs(ip: _Address, cidrs: list[_Network]) -> bool:
    for net in cidrs:
        try:
            if ip in net:
                return True
        except TypeError:
            # IPv4 vs IPv6 comparison: not applicable, ignored.
            continue
    return False


def _check_target(config: ScopeConfig, target: Target) -> Optional[dict[str, Any]]:
    """Evaluates a target against the scope. Returns a violation (dict) or ``None`` if it passes.

    Orden: deny PRIMERO (prioridad); luego allow (IP en cidr O host literal); luego ports
    (solo si el target trae puerto y hay ``ports`` definido).
    """
    # deny tiene prioridad: si cae en deny -> fuera de scope.
    if target.ip is not None and _in_cidrs(target.ip, config.deny_cidrs):
        return {"target": target.raw, "reason": "target en deny (CIDR)"}
    if target.host in config.deny_hosts:
        return {"target": target.raw, "reason": "target en deny (host)"}

    # allow: IP in an allowed cidr OR literal host in allow.
    in_allow = False
    if target.ip is not None and _in_cidrs(target.ip, config.allow_cidrs):
        in_allow = True
    elif target.host in config.allow_hosts:
        in_allow = True
    if not in_allow:
        return {"target": target.raw, "reason": "target fuera de allow"}

    # ports (opcional): solo se exige si el target trae puerto y hay ports definido.
    if config.ports is not None and target.port is not None and target.port not in config.ports:
        return {
            "target": target.raw,
            "reason": "puerto %d fuera de ports permitidos" % target.port,
        }

    return None


def evaluate(
    config: Optional[ScopeConfig],
    declared_targets: Optional[list[str]],
    command: str,
) -> ScopeDecision:
    """Gate core. Decides whether execution may proceed.

    Reglas, en orden:
      1. If the guard is not active (``is_enforcing`` False) -> passthrough
         (``allowed=True, enforced=False``). Compat total con el comportamiento actual.
      2. Active scope with NO declared ``targets`` -> block (strict decision): Hermes
         DEBE declarar los destinos del comando.
      3. Each declared target is normalized and evaluated (``_check_target``). Any target
         outside scope adds a violation.
      4. EXTRA BELT: targets extracted from the command that fall in deny, or are IPs and
         fall in no allow, add a violation. They never approve on their own.
      5. If there is any violation -> ``allowed=False``.
    """
    if not is_enforcing(config):
        return ScopeDecision(allowed=True, violations=[], enforced=False)

    assert config is not None  # is_enforcing garantiza config no-None

    violations: list[dict[str, Any]] = []

    if not declared_targets:
        violations.append(
            {
                "target": None,
                "reason": (
                    "scope activo pero no se declararon 'targets'; declara las "
                    "IP/host/URL destino de este comando"
                ),
            }
        )
        return ScopeDecision(allowed=False, violations=violations, enforced=True)

    # (3) Validar los targets declarados (fuente de verdad del gate).
    for raw in declared_targets:
        target = normalize_target(raw)
        violation = _check_target(config, target)
        if violation is not None:
            violations.append(violation)

    # (4) Extra belt: only BLOCKS obvious targets from the command, never approves.
    for extracted in extract_targets_from_command(command):
        if extracted.ip is not None and _in_cidrs(extracted.ip, config.deny_cidrs):
            violations.append(
                {
                    "target": extracted.raw,
                    "reason": "destino detectado en el comando cae en deny (CIDR)",
                }
            )
            continue
        if extracted.ip is not None and not _in_cidrs(extracted.ip, config.allow_cidrs):
            violations.append(
                {
                    "target": extracted.raw,
                    "reason": (
                        "IP detected in the command outside allow (declare it in "
                        "'targets' si es intencionada)"
                    ),
                }
            )

    return ScopeDecision(
        allowed=not violations, violations=violations, enforced=True
    )


def _allowed_summary(config: ScopeConfig) -> str:
    """Readable summary of what is allowed (cidrs + hosts) for the violation message."""
    parts: list[str] = [str(net) for net in config.allow_cidrs]
    parts.extend(sorted(config.allow_hosts))
    summary = ", ".join(parts) if parts else "(nada)"
    if config.ports is not None:
        summary += " | ports: %s" % ", ".join(str(p) for p in sorted(config.ports))
    return summary


def format_violation_message(decision: ScopeDecision, config: ScopeConfig) -> str:
    """Construye el texto ``SCOPE_VIOLATION: ...`` del error estructurado.

    Para "sin targets" produce el mensaje pidiendo declarar ``targets``; para targets fuera
    de scope lista el/los destino(s) rechazado(s) y el resumen de lo permitido.
    """
    no_targets = any(v.get("target") is None for v in decision.violations)
    if no_targets:
        return (
            "SCOPE_VIOLATION: scope is active but no 'targets' were declared; "
            "declare the IP/host/URL targets of this command"
        )
    seen: list[str] = []
    for v in decision.violations:
        target = v.get("target")
        if target is not None and str(target) not in seen:
            seen.append(str(target))
    rejected = ", ".join(seen)
    return (
        "SCOPE_VIOLATION: target %s is outside allowed scope (allowed: %s)"
        % (rejected, _allowed_summary(config))
    )
