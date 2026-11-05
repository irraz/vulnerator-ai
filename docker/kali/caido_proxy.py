"""Enrutado del tráfico del agente POR el proxy de Caido (STDLIB PURA) — captura HTTPS.

Es la LÓGICA testeable del enganche de arranque que hará que el OTRO tráfico web del agente
—los ``curl``/``nuclei`` que lanza ``kali_run``/``kali_exec`` y el navegador headless de
playwright-mcp— salga A TRAVÉS del proxy de Caido y quede CAPTURADO en su historial (el mismo
que ``caido_history`` consulta). Igual que ``caido_client`` / ``shell_exec`` / ``scope_guard``,
vive en un módulo aparte con SOLO la librería estándar (sin ``mcp`` ni ``requests``; HTTP por
``urllib``) para cubrirse con tests unitarios en el venv de dev, sin el SDK.

Qué resuelve: Caido escucha en ``0.0.0.0:8080`` para UI Y PROXY a la vez (log: "Listening on
0.0.0.0:8080 (Proxy, UI)"), así que el MISMO ``host:port`` de la API GraphQL es el endpoint del
proxy. Exportando ``HTTP_PROXY``/``HTTPS_PROXY`` hacia ese endpoint, un cliente que los respete
(curl, la mayoría de HTTP libs, Chromium) enruta su tráfico por Caido. Para que el HTTPS se
INTERCEPTE (y no reviente por certificado), hay que confiar en la CA por-instancia que Caido
genera en runtime y publica SIN auth en ``http://<caido>:8080/ca.crt`` (HTTP 200).

Reparto puro/efectos:
  - ``proxy_env`` / ``build_proxy_cli_args`` / el endpoint del proxy son PUROS (derivan de
    ``CAIDO_URL`` vía ``caido_client.resolve_url``): el núcleo cubierto por tests.
  - ``fetch_ca`` es la ÚNICA función con I/O de red en runtime (GET del PEM); en los tests se
    monkeypatchea ``urllib.request.urlopen``.
  - ``install_ca`` hace I/O de fichero + un ``subprocess.run`` del actualizador del trust store;
    en los tests se apunta a un ``dest`` temporal y a un ``update_cmd`` falso.
  - ``enable_capture`` ORQUESTA los tres (fetch -> install -> env); es lo que llamaría el hook.

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

# Se importa el MÓDULO (no los nombres sueltos) y se referencia ``caido_client.resolve_url`` /
# ``caido_client.CaidoError`` en cada llamada: así, si otro test recarga ``caido_client``
# (``importlib.reload``), siempre se usa la clase/func VIGENTE y el ``except`` sigue casando
# (un ``from caido_client import CaidoError`` capturaría una clase que una recarga deja obsoleta).
import caido_client

# --- Configuración por entorno (overridable; defaults para la red interna docker) -------

# Ruta del PEM de la CA por-instancia que Caido publica sin auth.
CA_PATH = os.environ.get("CAIDO_CA_PATH", "/ca.crt")

# Dónde se deposita la CA en el trust store del sistema (Debian/Kali). ``update-ca-certificates``
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

    Caido sirve UI y PROXY en el MISMO ``host:port``, así que se reutiliza
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
    except ValueError as exc:  # puerto no numérico / fuera de rango
        raise caido_client.CaidoError(
            f"CAIDO_URL con puerto inválido ({exc}): {base!r}"
        ) from exc
    host_fmt = f"[{host}]" if ":" in host else host
    return f"http://{host_fmt}:{port}"


def proxy_env(url: str | None = None) -> dict[str, Any]:
    """Variables de entorno de proxy para enrutar un subproceso POR Caido. Nunca lanza.

    Deriva ``HTTP_PROXY``/``HTTPS_PROXY`` (y sus variantes en minúscula, que muchas libs leen)
    del endpoint del proxy. Devuelve ``{'status':'ok','env':{...}}`` o, si no hay URL/es inválida,
    ``{'status':'failed','error':...}`` (fail-closed: el que llama NO propaga un proxy a medias).

    OJO (ver proposal): las llamadas del PROPIO kali-mcp a Caido NO deben ir por este proxy
    (bucle); eso se resuelve con ``NO_PROXY`` en la integración, no aquí.
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
    hay URL o es inválida, devuelve ``[]`` (fail-closed: sin arg el navegador va directo, no se
    inventa un endpoint). No lanza.
    """
    try:
        endpoint = proxy_endpoint(url)
    except caido_client.CaidoError:
        return []
    return [f"--proxy-server={endpoint}"]


# --- Descarga de la CA por-instancia (ÚNICA I/O de red en runtime) -----------------------


def fetch_ca(
    url: str | None = None, timeout: int = DEFAULT_CA_TIMEOUT_S
) -> dict[str, Any]:
    """GET del PEM de la CA de Caido (``<base>/ca.crt``). Nunca lanza por red/HTTP.

    Es la ÚNICA función de este módulo que sale a la red en runtime (en tests se monkeypatchea
    ``urllib.request.urlopen``). Caido publica la CA por-instancia SIN auth y con HTTP 200.
    Valida que el cuerpo PAREZCA un PEM (``-----BEGIN CERTIFICATE-----``); si no, es ``failed``
    (no se finge: un portal cautivo o un 200 con HTML no es un certificado).

    Returns:
      - ``{'status':'ok','pem':<str>}``
      - ``{'status':'unreachable','error':...}``  (no se pudo conectar / transporte roto)
      - ``{'status':'failed','error':...}``        (HTTP de error, URL inválida, o no es PEM)
    """
    try:
        base = caido_client.resolve_url(url)
    except caido_client.CaidoError as exc:
        return {"status": "failed", "error": str(exc)}
    ca_url = base + CA_PATH
    try:
        req = urllib.request.Request(ca_url, method="GET")
        # El esquema sale de CAIDO_URL (operador) y `resolve_url` sólo admite http/https: no hay
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
    except ValueError as exc:  # URL inválida (InvalidURL/espacios/corchetes)
        return {"status": "failed", "error": f"URL de la CA inválida ({ca_url}): {exc}"}

    pem = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
    if "-----BEGIN CERTIFICATE-----" not in pem:
        return {"status": "failed", "error": "respuesta no es un certificado PEM"}
    return {"status": "ok", "pem": pem}


# --- Instalación de la CA en el trust store (I/O de fichero + subprocess) -----------------


def install_ca(
    pem: str,
    dest: str = DEFAULT_CA_DEST,
    update_cmd: tuple[str, ...] = DEFAULT_UPDATE_CMD,
) -> dict[str, Any]:
    """Deposita el PEM en el trust store y refresca con ``update_cmd``. Nunca lanza.

    Flujo: valida ``pem`` (string no vacío, fail-closed) -> lo escribe en ``dest`` (I/O envuelta
    en try/except) -> ejecuta ``update_cmd`` con ``subprocess.run`` (captura salida, timeout,
    ``check=False``). ``dest`` y ``update_cmd`` son parámetros para que los tests apunten a un
    tmpdir y a un comando falso.

    NO se finge: si falta el binario del actualizador se devuelve ``absent``; si éste falla
    (returncode != 0) se devuelve ``failed`` con su salida; sólo un refresco exitoso es ``done``.

    Returns:
      - ``{'status':'done','path':dest}``
      - ``{'status':'absent','path':dest,'error':...}``   (binario del actualizador ausente)
      - ``{'status':'failed','path'?:dest,'error':...}``   (PEM inválido / I/O / actualizador falló)
    """
    if not isinstance(pem, str) or not pem.strip():
        return {
            "status": "failed",
            "error": "PEM vacío: no hay certificado que instalar.",
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
        # El binario del actualizador no está en la imagen: la CA quedó escrita pero el trust
        # store NO se refrescó. Se reporta tal cual (no se finge que el HTTPS quedó confiado).
        return {
            "status": "absent",
            "path": dest,
            "error": (
                f"actualizador del trust store ausente ({update_cmd[0] if update_cmd else '?'}): "
                f"{exc}. La CA se escribió pero el trust store NO se refrescó."
            ),
        }
    except (OSError, subprocess.SubprocessError) as exc:
        # Incluye TimeoutExpired: el actualizador se colgó o cascó. Estado reportable, no excepción.
        return {
            "status": "failed",
            "path": dest,
            "error": f"el actualizador del trust store falló: {type(exc).__name__}: {exc}",
        }

    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        return {
            "status": "failed",
            "path": dest,
            "returncode": proc.returncode,
            "error": f"{update_cmd[0]} devolvió {proc.returncode}: {detail}",
        }
    return {"status": "done", "path": dest}


# --- Orquestador: habilitar la captura (lo que llamaría el hook de arranque) --------------


def enable_capture(
    url: str | None = None,
    timeout: int = DEFAULT_CA_TIMEOUT_S,
    dest: str = DEFAULT_CA_DEST,
    update_cmd: tuple[str, ...] = DEFAULT_UPDATE_CMD,
) -> dict[str, Any]:
    """Habilita la captura por proxy: fetch_ca -> install_ca -> proxy_env. Nunca lanza.

    Es lo que un hook de arranque (opt-in, p. ej. ``CAIDO_PROXY_CAPTURE=1``) llamaría para dejar
    el entorno listo: confía la CA por-instancia y deriva las variables de proxy a propagar a los
    subprocesos (``kali_run``/``kali_exec``) y al navegador. Fail-closed: devuelve el dict de la
    PRIMERA etapa que falle (``unreachable``/``failed``/``absent``), sin continuar.

    Returns ``{'status':'done','ca_path':<dest>,'env':{...}}`` en éxito, o el dict de error de la
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
