"""Routing of the agent's traffic THROUGH Caido's proxy (PURE STDLIB) — HTTPS capture.

It is the testable LOGIC of the startup hook that makes the agent's OTHER web traffic
—los ``curl``/``nuclei`` que lanza ``kali_run``/``kali_exec`` y el navegador headless de
playwright-mcp — go THROUGH Caido's proxy and be CAPTURED in its history (the same
que ``caido_history`` consulta). Igual que ``caido_client`` / ``shell_exec`` / ``scope_guard``,
lives in a separate module with ONLY the standard library (no ``mcp`` or ``requests``; HTTP via
``urllib``) para cubrirse con tests unitarios en el venv de dev, sin el SDK.

What it solves: Caido listens on ``0.0.0.0:8080`` for UI AND PROXY at once (log: "Listening on
0.0.0.0:8080 (Proxy, UI)"), so the SAME ``host:port`` of the GraphQL API is the endpoint of the
proxy. Exportando ``HTTP_PROXY``/``HTTPS_PROXY`` hacia ese endpoint, un cliente que los respete
(curl, most HTTP libs, Chromium) routes its traffic through Caido. For HTTPS to be
INTERCEPTE (y no reviente por certificado), hay que confiar en la CA por-instancia que Caido
genera en runtime y publica SIN auth en ``http://<caido>:8080/ca.crt`` (HTTP 200).

Reparto puro/efectos:
  - ``proxy_env`` / ``build_proxy_cli_args`` / el endpoint del proxy son PUROS (derivan de
    ``CAIDO_URL`` via ``caido_client.resolve_url``): the core covered by tests.
  - ``fetch_ca`` is the ONLY function with network I/O at runtime (GET of the PEM); in tests it is
    monkeypatchea ``urllib.request.urlopen``.
  - ``install_ca`` hace I/O de fichero + un ``subprocess.run`` del actualizador del trust store;
    en los tests se apunta a un ``dest`` temporal y a un ``update_cmd`` falso.
  - ``enable_capture`` ORCHESTRATES the three (fetch -> install -> env); this is what the hook would call.

NO se finge: si el PEM no llega, no es un certificado, no se puede escribir, o el actualizador
del trust store falta/falla, se devuelve el estado real (``unreachable``/``failed``/``absent``),
nunca un "done" optimista. Todas las funciones devuelven dicts de estado y NUNCA lanzan.
"""

from __future__ import annotations

import http.client
import os
import subprocess  # nosec B404 - se ejecuta el actualizador del trust store de forma controlada
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlsplit

# Import the MODULE (not loose names) and reference ``caido_client.resolve_url`` /
# ``caido_client.CaidoError`` on each call: this way, if another test reloads ``caido_client``
# (``importlib.reload``), siempre se usa la clase/func VIGENTE y el ``except`` sigue casando
# (a ``from caido_client import CaidoError`` would capture a class left stale by a reload).
import caido_client

# --- Environment configuration (overridable; defaults for the docker internal network) -------

# Ruta del PEM de la CA por-instancia que Caido publica sin auth.
CA_PATH = os.environ.get("CAIDO_CA_PATH", "/ca.crt")

# Where the CA is placed in the system trust store (Debian/Kali). ``update-ca-certificates``
# consume ``/usr/local/share/ca-certificates/*.crt``.
DEFAULT_CA_DEST = (
    os.environ.get("CAIDO_CA_DEST") or ""
).strip() or "/usr/local/share/ca-certificates/caido.crt"

# Comando que refresca el trust store tras depositar la CA (parametrizable para tests).
DEFAULT_UPDATE_CMD: tuple[str, ...] = ("update-ca-certificates",)

# Timeout por defecto del GET del PEM (segundos).
DEFAULT_CA_TIMEOUT_S = 15

# Tope del tiempo que se le da al actualizador del trust store (no debe colgar el arranque).
_UPDATE_TIMEOUT_S = 60

# Tope defensivo del cuerpo de error que se lee (evita tragar MB de HTML de un 500).
_MAX_ERROR_BODY = 2000


# --- Endpoint del proxy (PURO: deriva de CAIDO_URL; sin red) -----------------------------


def proxy_endpoint(url: str | None = None) -> str:
    """Endpoint del proxy de Caido como ``http://<host>:<port>``. PURO.

    Caido serves UI and PROXY on the SAME ``host:port``, so it reuses
    ``caido_client.resolve_url`` para normalizar ``CAIDO_URL`` y se extrae ``host:port``. El
    esquema del VALOR es siempre ``http`` (un proxy HTTP se direcciona por http aunque tunelice
    HTTPS; el 8080 de Caido es texto plano). IPv6 se corchetea. Fail-closed: sin URL o con
    esquema no http/https, ``resolve_url`` lanza ``CaidoError``.
    """
    base = caido_client.resolve_url(
        url
    )  # http/https validado, sin barra final; lanza si falta
    parts = urlsplit(base)
    host = parts.hostname
    if not host:
        raise caido_client.CaidoError(f"CAIDO_URL sin host: {base!r}")
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError as exc:  # non-numeric / out-of-range port
        raise caido_client.CaidoError(
            f"CAIDO_URL with invalid port ({exc}): {base!r}"
        ) from exc
    host_fmt = f"[{host}]" if ":" in host else host
    return f"http://{host_fmt}:{port}"


def proxy_env(url: str | None = None) -> dict[str, Any]:
    """Variables de entorno de proxy para enrutar un subproceso POR Caido. Nunca lanza.

    Derives ``HTTP_PROXY``/``HTTPS_PROXY`` (and their lowercase variants, which many libs read)
    from the proxy endpoint. Returns ``{'status':'ok','env':{...}}`` or, if there is no URL/it is invalid,
    ``{'status':'failed','error':...}`` (fail-closed: el que llama NO propaga un proxy a medias).

    OJO (ver proposal): las llamadas del PROPIO kali-mcp a Caido NO deben ir por este proxy
    (loop); that is handled with ``NO_PROXY`` in the integration, not here.
    """
    try:
        endpoint = proxy_endpoint(url)
    except caido_client.CaidoError as exc:
        return {"status": "failed", "error": str(exc)}
    return {
        "status": "ok",
        "env": {
            "HTTP_PROXY": endpoint,
            "HTTPS_PROXY": endpoint,
            "http_proxy": endpoint,
            "https_proxy": endpoint,
        },
    }


def build_proxy_cli_args(url: str | None = None) -> list[str]:
    """Args estilo Chromium/Playwright para apuntar el navegador al proxy de Caido. PURO.

    Devuelve ``["--proxy-server=http://<host>:<port>"]`` para cablear el browser headless. Si no
    there is a URL or it is invalid, returns ``[]`` (fail-closed: without the arg the browser goes direct, it is not
    inventa un endpoint). No lanza.
    """
    try:
        endpoint = proxy_endpoint(url)
    except caido_client.CaidoError:
        return []
    return [f"--proxy-server={endpoint}"]


# --- Per-instance CA download (ONLY network I/O at runtime) -----------------------


def fetch_ca(
    url: str | None = None, timeout: int = DEFAULT_CA_TIMEOUT_S
) -> dict[str, Any]:
    """GET del PEM de la CA de Caido (``<base>/ca.crt``). Nunca lanza por red/HTTP.

    It is the ONLY function in this module that goes to the network at runtime (in tests it is monkeypatched
    ``urllib.request.urlopen``). Caido publica la CA por-instancia SIN auth y con HTTP 200.
    Valida que el cuerpo PAREZCA un PEM (``-----BEGIN CERTIFICATE-----``); si no, es ``failed``
    (no se finge: un portal cautivo o un 200 con HTML no es un certificado).

    Returns:
      - ``{'status':'ok','pem':<str>}``
      - ``{'status':'unreachable','error':...}``  (no se pudo conectar / transporte roto)
      - ``{'status':'failed','error':...}``        (HTTP error, invalid URL, or not PEM)
    """
    try:
        base = caido_client.resolve_url(url)
    except caido_client.CaidoError as exc:
        return {"status": "failed", "error": str(exc)}
    ca_url = base + CA_PATH
    try:
        req = urllib.request.Request(ca_url, method="GET")
        # The scheme comes from CAIDO_URL (operator) and `resolve_url` only allows http/https: there is no
        # file:// ni esquemas raros, y ninguna entrada de Hermes llega a esta URL.
        with urllib.request.urlopen(  # noqa: S310  # nosec B310
            req, timeout=timeout
        ) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        err_body = ""
        try:
            err_body = exc.read().decode("utf-8", errors="replace")[:_MAX_ERROR_BODY]
        except Exception:  # noqa: BLE001 - informativo
            pass
        return {
            "status": "failed",
            "http_status": exc.code,
            "error": err_body or f"HTTP {exc.code} al pedir la CA de Caido ({ca_url}).",
        }
    except urllib.error.URLError as exc:
        return {
            "status": "unreachable",
            "error": f"No se pudo conectar a Caido para la CA ({ca_url}): {exc.reason}",
        }
    except (OSError, http.client.HTTPException) as exc:
        return {
            "status": "unreachable",
            "error": f"Fallo de transporte al pedir la CA ({ca_url}): {type(exc).__name__}: {exc}",
        }
    except ValueError as exc:  # invalid URL (InvalidURL/spaces/brackets)
        return {"status": "failed", "error": f"invalid CA URL ({ca_url}): {exc}"}

    pem = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
    if "-----BEGIN CERTIFICATE-----" not in pem:
        return {"status": "failed", "error": "respuesta no es un certificado PEM"}
    return {"status": "ok", "pem": pem}


# --- Installing the CA in the trust store (file I/O + subprocess) -----------------


def install_ca(
    pem: str,
    dest: str = DEFAULT_CA_DEST,
    update_cmd: tuple[str, ...] = DEFAULT_UPDATE_CMD,
) -> dict[str, Any]:
    """Deposita el PEM en el trust store y refresca con ``update_cmd``. Nunca lanza.

    Flow: validate ``pem`` (non-empty string, fail-closed) -> write it to ``dest`` (wrapped I/O
    en try/except) -> ejecuta ``update_cmd`` con ``subprocess.run`` (captura salida, timeout,
    ``check=False``). ``dest`` and ``update_cmd`` are parameters so tests can point to a
    tmpdir y a un comando falso.

    No faking: if the updater binary is missing, ``absent`` is returned; if it fails
    (returncode != 0), ``failed`` is returned with its output; only a successful refresh is ``done``.

    Returns:
      - ``{'status':'done','path':dest}``
      - ``{'status':'absent','path':dest,'error':...}``   (binario del actualizador ausente)
      - ``{'status':'failed','path'?:dest,'error':...}``   (invalid PEM / I/O / updater failed)
    """
    if not isinstance(pem, str) or not pem.strip():
        return {
            "status": "failed",
            "error": "empty PEM: no certificate to install.",
        }

    try:
        dest_dir = os.path.dirname(dest)
        if dest_dir:
            os.makedirs(dest_dir, exist_ok=True)
        with open(dest, "w", encoding="utf-8") as fh:
            fh.write(pem)
    except OSError as exc:
        return {
            "status": "failed",
            "error": f"No se pudo escribir la CA en {dest}: {exc}",
        }

    try:
        proc = subprocess.run(  # noqa: S603  # nosec B603 - update_cmd es config del operador
            list(update_cmd),
            capture_output=True,
            text=True,
            timeout=_UPDATE_TIMEOUT_S,
            check=False,
        )
    except FileNotFoundError as exc:
        # The updater binary is not in the image: the CA was written but the trust
        # store was NOT refreshed. Reported as-is (no faking that HTTPS is trusted).
        return {
            "status": "absent",
            "path": dest,
            "error": (
                f"actualizador del trust store ausente ({update_cmd[0] if update_cmd else '?'}): "
                f"{exc}. The CA was written but the trust store was NOT refreshed."
            ),
        }
    except (OSError, subprocess.SubprocessError) as exc:
        # Includes TimeoutExpired: the updater hung or failed. Reportable status, not an exception.
        return {
            "status": "failed",
            "path": dest,
            "error": f"trust store updater failed: {type(exc).__name__}: {exc}",
        }

    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        return {
            "status": "failed",
            "path": dest,
            "returncode": proc.returncode,
            "error": f"{update_cmd[0]} returned {proc.returncode}: {detail}",
        }
    return {"status": "done", "path": dest}


# --- Orchestrator: enable capture (what the startup hook would call) --------------


def enable_capture(
    url: str | None = None,
    timeout: int = DEFAULT_CA_TIMEOUT_S,
    dest: str = DEFAULT_CA_DEST,
    update_cmd: tuple[str, ...] = DEFAULT_UPDATE_CMD,
) -> dict[str, Any]:
    """Habilita la captura por proxy: fetch_ca -> install_ca -> proxy_env. Nunca lanza.

    This is what a startup hook (opt-in, e.g. ``CAIDO_PROXY_CAPTURE=1``) would call to leave
    the environment ready: it trusts the per-instance CA and derives the proxy variables to propagate to the
    subprocesos (``kali_run``/``kali_exec``) y al navegador. Fail-closed: devuelve el dict de la
    PRIMERA etapa que falle (``unreachable``/``failed``/``absent``), sin continuar.

    Returns ``{'status':'done','ca_path':<dest>,'env':{...}}`` on success, or the error dict of the
    etapa que falle.
    """
    ca = fetch_ca(url, timeout=timeout)
    if ca["status"] != "ok":
        return ca
    installed = install_ca(ca["pem"], dest=dest, update_cmd=update_cmd)
    if installed["status"] != "done":
        return installed
    env = proxy_env(url)
    if env["status"] != "ok":
        return env
    return {"status": "done", "ca_path": installed["path"], "env": env["env"]}
