"""CDP proxy that fixes Chrome's anti-DNS-rebinding protection (PURE STDLIB: asyncio).

Problem: Chrome's debugging port (DevTools Protocol) rejects with 403 any request whose ``Host`` is
neither ``localhost`` nor an IP (anti-rebinding protection). ``playwright-mcp`` connects by service
name (``http://browser-view:9222``), so Chrome would reject it.

Solution: Chrome listens ONLY on loopback (``127.0.0.1:9223``) and this proxy listens on
``0.0.0.0:9222`` for the rest of the docker network. For each connection:

  1. Rewrite the request's ``Host:`` line to ``localhost:9223`` -> Chrome accepts it (both the HTTP
     discovery request and the DevTools WebSocket upgrade).
  2. On ``/json*`` responses (which carry ``webSocketDebuggerUrl``/``devtoolsFrontendUrl`` with the
     host Chrome saw, i.e. ``localhost:9223``), rewrite that host back to the one the CLIENT used, so
     the ws Playwright opens comes back to this proxy and not to some foreign localhost.

After the WebSocket upgrade (101) the bytes are piped raw in both directions: the proxy does not
interpret the CDP protocol, it only fixes the ``Host`` of the HTTP phase. UNTRUSTED DATA: here it
is only transported; the CDP payload is neither executed nor interpreted.

``rewrite_request_head`` and ``rewrite_json_body`` are PURE (the core covered by tests).
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
    """Rewrite the ``Host`` header to ``upstream``. Returns (new header, original host)."""
    m = _HOST_LINE.search(head)
    original = ""
    if m:
        original = m.group(0).split(b":", 1)[1].strip().decode("latin-1", "replace")
        head = _HOST_LINE.sub(b"Host: " + upstream.encode(), head, count=1)
    return head, original


_CONN_LINE = re.compile(rb"^Connection:[^\r\n]*\r\n", re.IGNORECASE | re.MULTILINE)
_KEEPALIVE_LINE = re.compile(rb"^Keep-Alive:[^\r\n]*\r\n", re.IGNORECASE | re.MULTILINE)


def force_close(head: bytes) -> bytes:
    """Force ``Connection: close`` on an HTTP (non-WebSocket) request so the upstream closes after
    responding and the proxy can read until EOF without hanging on keep-alive."""
    head = _CONN_LINE.sub(b"", head)
    head = _KEEPALIVE_LINE.sub(b"", head)
    head = head.replace(b"\r\n\r\n", b"\r\nConnection: close\r\n\r\n", 1)
    return head


def rewrite_json_body(body: bytes, client_host: str, upstream: str = UPSTREAM_HOST) -> bytes:
    """Rewrite the upstream host to the client's in ws:// URLs of the /json body."""
    if not client_host or client_host == upstream:
        return body
    out = body.replace(upstream.encode(), client_host.encode())
    # Chrome may use 127.0.0.1 instead of localhost depending on the version.
    alt = ("127.0.0.1:%d" % CHROME_PORT).encode()
    return out.replace(alt, client_host.encode())


async def _read_head(reader: asyncio.StreamReader) -> bytes:
    """Read up to the end of headers (CRLFCRLF)."""
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = await reader.read(1024)
        if not chunk:
            break
        data += chunk
        if len(data) > 1 << 20:  # 1 MiB of headers is absurd: cut it off
            break
    return data


async def read_http_response(reader: asyncio.StreamReader) -> bytes:
    """Read a complete HTTP response: headers + body by Content-Length (or until EOF).

    Chrome's /json endpoints respond with keep-alive and Content-Length, so you CANNOT read until
    EOF (it never comes). Content-Length is parsed and exactly that many bytes are read.
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
            # After the 101, pipe in both directions without touching anything.
            await asyncio.gather(_pipe(client_r, up_w), _pipe(up_r, client_w))
            return
        # Normal HTTP: read the response (by Content-Length), rewrite the body if it is /json.
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
    sys.stderr.write("[cdp-proxy] listening on %s:%d -> %s:%d\n"
                     % (listen_host, listen_port, CHROME_HOST, CHROME_PORT))
    sys.stderr.flush()
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
