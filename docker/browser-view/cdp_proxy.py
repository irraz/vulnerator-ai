"""Proxy CDP que arregla la protección anti-DNS-rebinding de Chrome (STDLIB PURA: asyncio).

Problema: el puerto de depuración de Chrome (DevTools Protocol) rechaza con 403 cualquier
petición cuyo ``Host`` no sea ``localhost`` ni una IP (protección anti-rebinding). ``playwright-mcp``
se conecta por nombre de servicio (``http://browser-view:9222``), así que Chrome lo rechazaría.

Solución: Chrome escucha SOLO en loopback (``127.0.0.1:9223``) y este proxy escucha en
``0.0.0.0:9222`` para el resto de la red docker. Por cada conexión:

  1. Reescribe la línea ``Host:`` de la petición a ``localhost:9223`` -> Chrome la acepta
     (tanto la petición HTTP de descubrimiento como el upgrade WebSocket de DevTools).
  2. En las respuestas de ``/json*`` (que traen ``webSocketDebuggerUrl``/``devtoolsFrontendUrl``
     con el host que Chrome vio, es decir ``localhost:9223``), reescribe ese host al que usó el
     CLIENTE, para que el ws que playwright abra vuelva a este proxy y no a un localhost ajeno.

Tras el upgrade WebSocket (101) los bytes se canalizan en crudo en ambos sentidos: el proxy no
interpreta el protocolo CDP, solo arregla el ``Host`` de la fase HTTP. DATO NO CONFIABLE: aquí
solo se transporta; el payload CDP no se ejecuta ni se interpreta.

``rewrite_request_head`` y ``rewrite_json_body`` son PURAS (el núcleo cubierto por tests).
"""

from __future__ import annotations

import asyncio
import re
import sys

CHROME_HOST = "127.0.0.1"
CHROME_PORT = 9223
UPSTREAM_HOST = "localhost:%d" % CHROME_PORT

_HOST_LINE = re.compile(rb"^Host:[^\r\n]*", re.IGNORECASE | re.MULTILINE)


def rewrite_request_head(head: bytes, upstream: str = UPSTREAM_HOST) -> tuple[bytes, str]:
    """Reescribe la cabecera ``Host`` a ``upstream``. Devuelve (cabecera nueva, host original)."""
    m = _HOST_LINE.search(head)
    original = ""
    if m:
        original = m.group(0).split(b":", 1)[1].strip().decode("latin-1", "replace")
        head = _HOST_LINE.sub(b"Host: " + upstream.encode(), head, count=1)
    return head, original


_CONN_LINE = re.compile(rb"^Connection:[^\r\n]*\r\n", re.IGNORECASE | re.MULTILINE)
_KEEPALIVE_LINE = re.compile(rb"^Keep-Alive:[^\r\n]*\r\n", re.IGNORECASE | re.MULTILINE)


def force_close(head: bytes) -> bytes:
    """Fuerza ``Connection: close`` en una petición HTTP (no-WebSocket) para que el upstream
    cierre tras responder y el proxy pueda leer hasta EOF sin colgarse con keep-alive."""
    head = _CONN_LINE.sub(b"", head)
    head = _KEEPALIVE_LINE.sub(b"", head)
    head = head.replace(b"\r\n\r\n", b"\r\nConnection: close\r\n\r\n", 1)
    return head


def rewrite_json_body(body: bytes, client_host: str, upstream: str = UPSTREAM_HOST) -> bytes:
    """Reescribe el host upstream por el del cliente en URLs ws:// del cuerpo /json."""
    if not client_host or client_host == upstream:
        return body
    out = body.replace(upstream.encode(), client_host.encode())
    # Chrome puede usar 127.0.0.1 en vez de localhost según versión.
    alt = ("127.0.0.1:%d" % CHROME_PORT).encode()
    return out.replace(alt, client_host.encode())


async def _read_head(reader: asyncio.StreamReader) -> bytes:
    """Lee hasta el fin de cabeceras (CRLFCRLF)."""
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = await reader.read(1024)
        if not chunk:
            break
        data += chunk
        if len(data) > 1 << 20:  # 1 MiB de cabeceras es absurdo: corta
            break
    return data


async def read_http_response(reader: asyncio.StreamReader) -> bytes:
    """Lee una respuesta HTTP completa: cabeceras + cuerpo por Content-Length (o hasta EOF).

    Los endpoints /json de Chrome responden con keep-alive y Content-Length, así que NO se
    puede leer hasta EOF (no llega). Se parsea Content-Length y se leen exactamente esos bytes.
    """
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = await reader.read(4096)
        if not chunk:
            return head
        head += chunk
    sep = head.find(b"\r\n\r\n")
    headers, body = head[: sep + 4], head[sep + 4:]
    m = re.search(rb"(?i)content-length:\s*(\d+)", headers)
    if m:
        need = int(m.group(1)) - len(body)
        while need > 0:
            chunk = await reader.read(min(65536, need))
            if not chunk:
                break
            body += chunk
            need -= len(chunk)
    else:
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                break
            body += chunk
    return headers + body


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                break
            writer.write(chunk)
            await writer.drain()
    except (ConnectionError, asyncio.IncompleteReadError):
        pass
    finally:
        with_suppress_close(writer)


def with_suppress_close(writer: asyncio.StreamWriter) -> None:
    try:
        writer.close()
    except Exception:
        pass


async def _handle(client_r: asyncio.StreamReader, client_w: asyncio.StreamWriter) -> None:
    try:
        head = await _read_head(client_r)
        if not head:
            return with_suppress_close(client_w)
        new_head, original_host = rewrite_request_head(head)
        is_ws = b"upgrade: websocket" in head.lower()
        if not is_ws:
            new_head = force_close(new_head)
        sep = new_head.find(b"\r\n\r\n")
        leftover = new_head[sep + 4:] if sep != -1 else b""
        try:
            up_r, up_w = await asyncio.open_connection(CHROME_HOST, CHROME_PORT)
        except OSError:
            client_w.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            await client_w.drain()
            return with_suppress_close(client_w)
        up_w.write(new_head[: sep + 4] if sep != -1 else new_head)
        if leftover:
            up_w.write(leftover)
        await up_w.drain()

        is_json = head.split(b" ", 2)[1].startswith(b"/json") if head.count(b" ") >= 2 else False

        if is_ws:
            # Tras el 101, canaliza en ambos sentidos sin tocar nada.
            await asyncio.gather(_pipe(client_r, up_w), _pipe(up_r, client_w))
            return
        # HTTP normal: lee la respuesta (por Content-Length), reescribe el cuerpo si es /json.
        resp = await read_http_response(up_r)
        if is_json:
            hsep = resp.find(b"\r\n\r\n")
            if hsep != -1:
                rheaders, rbody = resp[:hsep + 4], resp[hsep + 4:]
                rbody = rewrite_json_body(rbody, original_host)
                rheaders = re.sub(rb"(?i)content-length:[^\r\n]*",
                                  b"Content-Length: %d" % len(rbody), rheaders, count=1)
                resp = rheaders + rbody
        client_w.write(resp)
        await client_w.drain()
        with_suppress_close(up_w)
    except (ConnectionError, asyncio.IncompleteReadError):
        pass
    finally:
        with_suppress_close(client_w)


async def main(listen_host: str = "0.0.0.0", listen_port: int = 9222) -> None:
    server = await asyncio.start_server(_handle, listen_host, listen_port)
    sys.stderr.write("[cdp-proxy] escuchando en %s:%d -> %s:%d\n"
                     % (listen_host, listen_port, CHROME_HOST, CHROME_PORT))
    sys.stderr.flush()
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
