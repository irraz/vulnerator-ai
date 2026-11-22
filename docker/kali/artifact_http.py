"""Servidor HTTP de artefactos de `kali-mcp` — el canal del plano de DATOS.

STDLIB PURA (``http.server``), independiente de ``mcp``/``anyio`` (vive en su propio
module, testable without the SDK). It serves the RAW result staged by ``artifact_store``
al cliente, que lo baja por STREAM. Es el transporte que sustituye al evento SSE de
1 MiB: the large blob travels HERE (HTTP chunked by reference), NEVER through the channel
de control (MCP).

Frontera de seguridad:
  - Exige la cabecera ``X-Artifact-Token`` == ``KALI_ARTIFACTS_TOKEN`` (403 sin ella o
    if it does not match; constant-time comparison). Fail-closed: ``make_server`` does NOT
    arranca sin token.
  - Confines paths via ``artifact_store.resolve`` (``..``/separators -> 400).
  - 404 si el artefacto no existe. El crudo es DATO NO CONFIABLE: se transporta
    verbatim, no se interpreta ni se loguea su contenido.
  - NOT exposed to the host (docker internal network only); orchestration decides this.
"""

from __future__ import annotations

import hmac
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit

import artifact_store

# Prefijo de ruta del endpoint de datos. Espejo del que el cliente compone al bajar.
_PREFIX = "/artifacts/"

# Chunk size when serving (64 KiB): stream, not "all at once".
_CHUNK_SIZE = 65536

# Cabecera del token compartido entre servidor y cliente.
_TOKEN_HEADER = "X-Artifact-Token"


class _ArtifactHandler(BaseHTTPRequestHandler):
    """Sirve ``GET /artifacts/<execution_id>/<name>`` por stream, tras validar token."""

    server_version = "kali-artifacts/1.0"

    # Silencia el log por defecto: la ruta puede contener dato no confiable y no se
    # logs verbatim. If tracing were needed, it would go through its own channel.
    def log_message(self, *args, **kwargs) -> None:  # noqa: D401, ANN002, ANN003
        return

    def _deny(self, code: int, reason: str) -> None:
        """Responde un error corto (texto plano) sin filtrar el dato pedido."""
        body = reason.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _token_ok(self) -> bool:
        expected = getattr(self.server, "artifact_token", "") or ""
        provided = self.headers.get(_TOKEN_HEADER, "") or ""
        if not provided:
            return False
        # Constant-time comparison (avoids a timing oracle).
        return hmac.compare_digest(provided, expected)

    def do_GET(self) -> None:  # noqa: N802 - firma de BaseHTTPRequestHandler
        path = urlsplit(self.path).path

        # 1) Token primero: sin credencial no se revela nada (403).
        if not self._token_ok():
            self._deny(403, "forbidden: missing or invalid artifact token")
            return

        # 2) Only the artifacts endpoint.
        if not path.startswith(_PREFIX):
            self._deny(404, "not found")
            return

        # 3) Parsear <execution_id>/<name>; un multi-segmento se reconstruye como name
        #    con '/' y lo rechaza el confinamiento de resolve (-> 400).
        rest = path[len(_PREFIX):]
        parts = rest.split("/")
        if len(parts) < 2 or not parts[0]:
            self._deny(400, "bad request: expected /artifacts/<execution_id>/<name>")
            return
        execution_id = unquote(parts[0])
        name = unquote("/".join(parts[1:]))

        # 4) Confinamiento (traversal/separadores/absoluta) -> 400.
        try:
            target = artifact_store.resolve(execution_id, name)
        except ValueError:
            self._deny(400, "bad request: invalid artifact path")
            return

        # 5) Existencia -> 404.
        if not target.is_file():
            self._deny(404, "not found")
            return

        # 6) Stream the file with Content-Length + sha256 (from meta if present).
        entry = artifact_store.stat(execution_id, name)
        size = entry["size"] if entry and "size" in entry else target.stat().st_size
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(size))
        if entry and entry.get("sha256"):
            self.send_header("X-Artifact-Sha256", str(entry["sha256"]))
        self.end_headers()
        with target.open("rb") as handle:
            while True:
                chunk = handle.read(_CHUNK_SIZE)
                if not chunk:
                    break
                self.wfile.write(chunk)


def make_server(host: str, port: int, token: str) -> ThreadingHTTPServer:
    """Crea (sin arrancar) el servidor HTTP de artefactos ligado a ``token``.

    Fail-closed: raises ``ValueError`` if ``token`` is empty — a data endpoint without
    a token would be an open channel to potentially sensitive data. ``port=0``
    picks an ephemeral port (useful in tests; the real one is read from ``server.server_address``).
    """
    if not token:
        raise ValueError(
            "KALI_ARTIFACTS_TOKEN empty: the artifacts server does not start without "
            "token (fail-closed)."
        )
    server = ThreadingHTTPServer((host, port), _ArtifactHandler)
    # The handler reads the token from the server (not a global): a single source of truth.
    server.artifact_token = token  # type: ignore[attr-defined]
    return server


def serve_in_thread(
    host: str, port: int, token: str
) -> tuple[ThreadingHTTPServer, threading.Thread]:
    """Arranca el servidor en un hilo DEMONIO y devuelve ``(server, thread)``.

    No bloquea: el proceso principal sigue a ``mcp.run(...)`` (plano de control). El
    caller puede ``server.shutdown()`` para pararlo (tests). El hilo es daemon para no
    impedir la salida del proceso.
    """
    server = make_server(host, port, token)
    thread = threading.Thread(
        target=server.serve_forever, name="kali-artifacts-http", daemon=True
    )
    thread.start()
    return server, thread
