#!/usr/bin/env python3
"""
TCP SNI Proxy — routes HTTPS by SNI hostname (passthrough, no TLS termination)
or by hostname + path (with TLS termination using a configured certificate).

Route keys in config:
  "hostname"        → passthrough to backend (TLS untouched)
  "hostname/path"   → terminate TLS, route by path prefix, forward to backend

Usage:
  python3 proxy.py [config.json]
  python3 proxy.py --help

Signals:
  SIGHUP  — reload config without restarting
"""

import asyncio
import json
import logging
import re
import signal
import ssl
import struct
import sys
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger("proxy")


# ── Config ────────────────────────────────────────────────────────────────────

DEFAULT_CONFIG: dict = {
    "listen_host": "0.0.0.0",
    "listen_ports": [443],
    "tls_routes": {
        "padel.freecourts.nl": {"host": "192.168.2.76", "port": 8443, "name": "padel", "enabled": True},
        "home.budie.eu":       {"host": "192.168.2.76", "port": 300,  "name": "home",  "enabled": True},
    },
    "connect_timeout": 10,
    "read_timeout": 5,
    "admin_host": "0.0.0.0",
    "admin_port": 8888,
    "tls_cert": None,
    "tls_key": None,
}


@dataclass
class Backend:
    host: str
    port: int
    name: str
    enabled: bool = True
    backend_ssl: bool = False    # connect to backend via HTTPS
    strip_path: bool = True      # strip matched path prefix before forwarding
    rewrite_paths: bool = False  # rewrite Location/HTML paths in responses


@dataclass
class Config:
    listen_host: str
    listen_ports: list[int]
    tls_routes: dict[str, Backend]   # key: "hostname" or "hostname/path"
    connect_timeout: int
    read_timeout: int
    admin_host: str = "0.0.0.0"
    admin_port: int = 8888
    tls_cert: Optional[str] = None
    tls_key: Optional[str] = None


def _parse_backend(d: dict) -> Backend:
    return Backend(
        host=d["host"],
        port=d["port"],
        name=d["name"],
        enabled=d.get("enabled", True),
        backend_ssl=d.get("backend_ssl", False),
        strip_path=d.get("strip_path", True),
        rewrite_paths=d.get("rewrite_paths", False),
    )


def load_config(path: Path) -> Config:
    if path.exists():
        raw = json.loads(path.read_text())
        logger.info(f"Config loaded from {path}")
    else:
        raw = DEFAULT_CONFIG
        path.write_text(json.dumps(DEFAULT_CONFIG, indent=2))
        logger.info(f"No config found — wrote default to {path}")

    raw_ports = raw.get("listen_ports") or raw.get("listen_port", 443)
    if isinstance(raw_ports, int):
        raw_ports = [raw_ports]

    return Config(
        listen_host=raw.get("listen_host", "0.0.0.0"),
        listen_ports=raw_ports,
        tls_routes={h: _parse_backend(b) for h, b in raw.get("tls_routes", {}).items()},
        connect_timeout=raw.get("connect_timeout", 10),
        read_timeout=raw.get("read_timeout", 5),
        admin_host=raw.get("admin_host", "0.0.0.0"),
        admin_port=raw.get("admin_port", 8888),
        tls_cert=raw.get("tls_cert"),
        tls_key=raw.get("tls_key"),
    )


def save_config(cfg: Config, path: Path) -> None:
    data = {
        "listen_host": cfg.listen_host,
        "listen_ports": cfg.listen_ports,
        "tls_routes": {
            h: {
                "host": b.host, "port": b.port, "name": b.name,
                "enabled": b.enabled, "backend_ssl": b.backend_ssl,
                "strip_path": b.strip_path, "rewrite_paths": b.rewrite_paths,
            }
            for h, b in cfg.tls_routes.items()
        },
        "connect_timeout": cfg.connect_timeout,
        "read_timeout": cfg.read_timeout,
        "admin_host": cfg.admin_host,
        "admin_port": cfg.admin_port,
        "tls_cert": cfg.tls_cert,
        "tls_key": cfg.tls_key,
    }
    path.write_text(json.dumps(data, indent=2))


def log_config(cfg: Config) -> None:
    ports = ", ".join(str(p) for p in cfg.listen_ports)
    logger.info(f"Listen: {cfg.listen_host}  ports: {ports}")
    if cfg.tls_cert:
        logger.info(f"TLS termination cert: {cfg.tls_cert}")
    logger.info("Routes:")
    for key, be in cfg.tls_routes.items():
        state = "ON " if be.enabled else "OFF"
        mode = " [SSL→be]" if be.backend_ssl else ""
        logger.info(f"  [{state}] {key:<45} → {be.name} ({be.host}:{be.port}){mode}")


# ── Route index ───────────────────────────────────────────────────────────────

# RouteIndex: hostname → list of (path_prefix, Backend), sorted longest-first
RouteIndex = dict[str, list[tuple[str, "Backend"]]]


def build_route_index(routes: dict[str, Backend]) -> RouteIndex:
    index: RouteIndex = {}
    for key, backend in routes.items():
        if "/" in key:
            hostname, suffix = key.split("/", 1)
            path_prefix = "/" + suffix
        else:
            hostname = key
            path_prefix = ""
        index.setdefault(hostname.lower(), []).append((path_prefix, backend))
    for hostname in index:
        index[hostname].sort(key=lambda x: len(x[0]), reverse=True)
    return index


def hostname_needs_termination(hostname: str, index: RouteIndex) -> bool:
    return any(p != "" for p, _ in index.get(hostname.lower(), []))


def find_route(hostname: str, path: str, index: RouteIndex) -> Optional[tuple[str, Backend]]:
    """Return (path_prefix, backend) for best match, or None."""
    for path_prefix, backend in index.get(hostname.lower(), []):
        if path_prefix and path.startswith(path_prefix):
            return path_prefix, backend
    for path_prefix, backend in index.get(hostname.lower(), []):
        if path_prefix == "":
            return "", backend
    return None


# ── SSL context ───────────────────────────────────────────────────────────────

def build_ssl_ctx(cert: str, key: str) -> Optional[ssl.SSLContext]:
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        return ctx
    except Exception as exc:
        logger.error(f"Failed to load TLS cert/key: {exc}")
        return None


# ── SNI extraction ────────────────────────────────────────────────────────────

def _is_tls(data: bytes) -> bool:
    return (
        len(data) >= 3
        and data[0] == 0x16
        and data[1] == 0x03
        and data[2] in (0x00, 0x01, 0x02, 0x03, 0x04)
    )


def extract_sni(data: bytes) -> Optional[str]:
    try:
        if not _is_tls(data) or len(data) < 6:
            return None
        pos = 5
        if data[pos] != 0x01:
            return None
        pos += 4
        pos += 2
        pos += 32
        if pos >= len(data):
            return None
        pos += 1 + data[pos]
        if pos + 2 > len(data):
            return None
        cs_len = struct.unpack("!H", data[pos: pos + 2])[0]
        pos += 2 + cs_len
        if pos >= len(data):
            return None
        pos += 1 + data[pos]
        if pos + 2 > len(data):
            return None
        ext_end = pos + 2 + struct.unpack("!H", data[pos: pos + 2])[0]
        pos += 2
        while pos + 4 <= ext_end and pos + 4 <= len(data):
            ext_type = struct.unpack("!H", data[pos: pos + 2])[0]
            ext_len  = struct.unpack("!H", data[pos + 2: pos + 4])[0]
            pos += 4
            if ext_type == 0x0000:
                if pos + 5 <= len(data):
                    name_type = data[pos + 2]
                    name_len  = struct.unpack("!H", data[pos + 3: pos + 5])[0]
                    if name_type == 0x00 and pos + 5 + name_len <= len(data):
                        return data[pos + 5: pos + 5 + name_len].decode("ascii")
            pos += ext_len
        return None
    except Exception:
        return None


# ── TLS Terminator ────────────────────────────────────────────────────────────

class TLSTerminator:
    """
    Terminates TLS on an existing asyncio stream using ssl.MemoryBIO.
    This allows SNI extraction before the handshake by replaying the
    already-read ClientHello bytes into the SSL engine.
    """

    def __init__(
        self,
        ssl_ctx: ssl.SSLContext,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        self.incoming = ssl.MemoryBIO()
        self.outgoing = ssl.MemoryBIO()
        self.ssl_obj = ssl_ctx.wrap_bio(self.incoming, self.outgoing, server_side=True)
        self._reader = reader
        self._writer = writer

    async def do_handshake(self, initial_data: bytes) -> None:
        """Complete TLS handshake; initial_data is the already-read ClientHello."""
        self.incoming.write(initial_data)
        while True:
            try:
                self.ssl_obj.do_handshake()
                break
            except ssl.SSLWantReadError:
                await self._flush()
                more = await asyncio.wait_for(self._reader.read(16384), timeout=10)
                if not more:
                    raise ConnectionError("Client closed during TLS handshake")
                self.incoming.write(more)
            except ssl.SSLWantWriteError:
                await self._flush()
        await self._flush()

    async def _flush(self) -> None:
        if self.outgoing.pending:
            self._writer.write(self.outgoing.read())
            await self._writer.drain()

    async def read(self, n: int = 16384, timeout: Optional[float] = None) -> bytes:
        while True:
            try:
                return self.ssl_obj.read(n)
            except ssl.SSLWantReadError:
                try:
                    coro = self._reader.read(16384)
                    more = await (asyncio.wait_for(coro, timeout=timeout) if timeout else coro)
                except asyncio.TimeoutError:
                    return b""
                if not more:
                    return b""
                self.incoming.write(more)
            except ssl.SSLZeroReturnError:
                return b""

    async def write(self, data: bytes) -> None:
        self.ssl_obj.write(data)
        await self._flush()

    async def close(self) -> None:
        try:
            self.ssl_obj.unwrap()
            await self._flush()
        except Exception:
            pass
        try:
            self._writer.close()
            await self._writer.wait_closed()
        except Exception:
            pass


# ── Passthrough pipe ──────────────────────────────────────────────────────────

async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, label: str) -> int:
    total = 0
    try:
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                break
            writer.write(chunk)
            await writer.drain()
            total += len(chunk)
    except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
        pass
    except Exception as exc:
        logger.debug(f"pipe {label}: {exc}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
    return total


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def rewrite_http_request(
    headers_bytes: bytes,
    path_prefix: str,
    strip_path: bool,
    backend_host: str,
    backend_port: int,
) -> bytes:
    """Rewrite request line (strip path prefix) and Host header."""
    try:
        text = headers_bytes.decode("utf-8", errors="replace")
        lines = text.split("\r\n")
        parts = lines[0].split(" ", 2)
        if len(parts) >= 2:
            method, path = parts[0], parts[1]
            version = parts[2] if len(parts) > 2 else "HTTP/1.1"
            if strip_path and path_prefix and path.startswith(path_prefix):
                new_path = path[len(path_prefix):]
                if not new_path.startswith("/"):
                    new_path = "/" + new_path
                path = new_path or "/"
            lines[0] = f"{method} {path} {version}"
        new_lines = []
        for line in lines:
            if line.lower().startswith("host:"):
                new_lines.append(f"Host: {backend_host}:{backend_port}")
            else:
                new_lines.append(line)
        return "\r\n".join(new_lines).encode("utf-8")
    except Exception:
        return headers_bytes


# ── Response rewriting ────────────────────────────────────────────────────────

def _rewrite_html_body(body: bytes, prefix: str) -> bytes:
    """Prefix all absolute paths in HTML with prefix (e.g. /pfsense)."""
    try:
        text = body.decode("utf-8", errors="replace")
        esc = re.escape(prefix)
        # href="/...", src="/...", action="/..."  — skip if already prefixed
        text = re.sub(
            r'(?i)((?:href|src|action|data-url)\s*=\s*["\'])(/(?!' + esc[1:] + r'/))',
            lambda m: m.group(1) + prefix + m.group(2),
            text,
        )
        # window.location = "/..." or location.href = "/..."
        text = re.sub(
            r"""((?:window\.location|location\.href)\s*=\s*['"])(/(?!""" + esc[1:] + r"/)')",
            lambda m: m.group(1) + prefix + m.group(2),
            text,
        )
        return text.encode("utf-8")
    except Exception:
        return body


def _decode_chunked(data: bytes) -> bytes:
    """Decode HTTP chunked transfer encoding."""
    out = bytearray()
    pos = 0
    try:
        while pos < len(data):
            end = data.index(b"\r\n", pos)
            size = int(data[pos:end], 16)
            if size == 0:
                break
            pos = end + 2
            out.extend(data[pos: pos + size])
            pos += size + 2  # skip trailing \r\n
    except Exception:
        pass
    return bytes(out)


def _parse_response_headers(
    headers_data: bytes, prefix: str
) -> tuple[list[str], bool, int, bool]:
    """
    Parse and rewrite response headers.
    Returns (lines, is_html, content_length, is_chunked).
    """
    lines = headers_data.decode("utf-8", errors="replace").rstrip("\r\n").split("\r\n")
    new_lines = [lines[0]]
    is_html = False
    content_length = -1
    is_chunked = False

    for line in lines[1:]:
        lower = line.lower()
        if lower.startswith("location:"):
            val = line.split(":", 1)[1].strip()
            if val.startswith("/") and not val.startswith(prefix):
                line = f"Location: {prefix}{val}"
        elif lower.startswith("set-cookie:") and "path=/" in lower:
            line = re.sub(
                r"(?i)(;\s*path=)(/)(?!" + re.escape(prefix[1:]) + r"/)",
                lambda m: m.group(1) + prefix + m.group(2),
                line,
            )
        elif lower.startswith("content-type:") and "text/html" in lower:
            is_html = True
        elif lower.startswith("content-length:"):
            try:
                content_length = int(line.split(":", 1)[1].strip())
            except ValueError:
                pass
        elif lower.startswith("transfer-encoding:") and "chunked" in lower:
            is_chunked = True
        new_lines.append(line)

    return new_lines, is_html, content_length, is_chunked


async def _proxy_response(
    be_reader: asyncio.StreamReader,
    tls: "TLSTerminator",
    prefix: str,
) -> tuple[int, bool]:
    """
    Read one HTTP response from backend, rewrite if needed, send to client.
    Returns (bytes_sent, keep_alive).
    """
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = await be_reader.read(4096)
        if not chunk:
            if buf:
                await tls.write(buf)
            return len(buf), False
        buf += chunk

    sep = buf.index(b"\r\n\r\n")
    headers_data = buf[: sep + 4]
    remainder = buf[sep + 4:]

    new_lines, is_html, content_length, is_chunked = _parse_response_headers(headers_data, prefix)

    # Determine keep-alive from status + headers
    status_code = 0
    try:
        status_code = int(new_lines[0].split()[1])
    except Exception:
        pass
    keep_alive = status_code not in (204, 304)
    for line in new_lines[1:]:
        if line.lower().startswith("connection:") and "close" in line.lower():
            keep_alive = False

    # No body for 1xx, 204, 304
    if status_code in (204, 304) or (100 <= status_code < 200):
        await tls.write("\r\n".join(new_lines).encode("utf-8"))
        return 0, False

    if is_html:
        # Read full body to rewrite it
        body = remainder
        if content_length >= 0:
            remaining = content_length - len(remainder)
            while remaining > 0:
                chunk = await be_reader.read(min(remaining, 65536))
                if not chunk:
                    break
                body += chunk
                remaining -= len(chunk)
        elif is_chunked:
            raw = remainder
            while not (b"\r\n0\r\n\r\n" in raw or raw.endswith(b"0\r\n\r\n")):
                chunk = await be_reader.read(65536)
                if not chunk:
                    break
                raw += chunk
            body = _decode_chunked(raw)
            is_chunked = False
        else:
            while True:
                chunk = await be_reader.read(65536)
                if not chunk:
                    break
                body += chunk
            keep_alive = False

        body = _rewrite_html_body(body, prefix)

        final_lines = []
        has_cl = False
        for line in new_lines:
            if line.lower().startswith("transfer-encoding:"):
                continue
            if line.lower().startswith("content-length:"):
                final_lines.append(f"Content-Length: {len(body)}")
                has_cl = True
            else:
                final_lines.append(line)
        if not has_cl:
            final_lines.insert(1, f"Content-Length: {len(body)}")

        await tls.write("\r\n".join(final_lines).encode("utf-8"))
        await tls.write(body)
        return len(body), keep_alive

    else:
        # Non-HTML: stream body, headers already rewritten
        await tls.write("\r\n".join(new_lines).encode("utf-8"))
        total = 0

        if content_length >= 0:
            await tls.write(remainder)
            total += len(remainder)
            remaining = content_length - len(remainder)
            while remaining > 0:
                chunk = await be_reader.read(min(remaining, 65536))
                if not chunk:
                    break
                await tls.write(chunk)
                total += len(chunk)
                remaining -= len(chunk)
        elif is_chunked:
            await tls.write(remainder)
            total += len(remainder)
            while not (b"\r\n0\r\n\r\n" in remainder or remainder.endswith(b"0\r\n\r\n")):
                remainder = await be_reader.read(65536)
                if not remainder:
                    break
                await tls.write(remainder)
                total += len(remainder)
        else:
            await tls.write(remainder)
            total += len(remainder)
            while True:
                chunk = await be_reader.read(65536)
                if not chunk:
                    break
                await tls.write(chunk)
                total += len(chunk)
            keep_alive = False

        return total, keep_alive


async def _http_proxy_loop(
    tls: "TLSTerminator",
    be_reader: asyncio.StreamReader,
    be_writer: asyncio.StreamWriter,
    path_prefix: str,
    backend: "Backend",
    leftover: bytes,
) -> tuple[int, int]:
    """
    Full HTTP/1.1 request-response loop with path and response rewriting.
    Used when backend.rewrite_paths is True.
    """
    up = down = 0

    # Forward the already-read leftover request body bytes
    if leftover:
        be_writer.write(leftover)
        await be_writer.drain()
        up += len(leftover)

    while True:
        # Read and rewrite one response
        resp_bytes, keep_alive = await _proxy_response(be_reader, tls, path_prefix)
        down += resp_bytes

        if not keep_alive:
            break

        # Read next request from client
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = await tls.read(4096, timeout=30)
            if not chunk:
                return up, down
            buf += chunk

        sep = buf.index(b"\r\n\r\n")
        req_headers = buf[: sep + 4]
        req_leftover = buf[sep + 4:]

        # Parse request body length
        req_content_length = 0
        req_chunked = False
        for line in req_headers.decode("utf-8", errors="replace").split("\r\n")[1:]:
            lower = line.lower()
            if lower.startswith("content-length:"):
                try:
                    req_content_length = int(line.split(":", 1)[1].strip())
                except ValueError:
                    pass
            elif lower.startswith("transfer-encoding:") and "chunked" in lower:
                req_chunked = True

        # Rewrite and forward request
        new_req = rewrite_http_request(req_headers, path_prefix, backend.strip_path, backend.host, backend.port)
        be_writer.write(new_req)
        up += len(new_req)

        # Forward request body
        if req_content_length > 0:
            body = req_leftover
            remaining = req_content_length - len(req_leftover)
            while remaining > 0:
                chunk = await tls.read(min(remaining, 65536))
                if not chunk:
                    break
                body += chunk
                remaining -= len(chunk)
            be_writer.write(body)
            up += len(body)
        elif req_chunked:
            buf = req_leftover
            while not (b"\r\n0\r\n\r\n" in buf or buf.endswith(b"0\r\n\r\n")):
                be_writer.write(buf)
                up += len(buf)
                buf = await tls.read(65536)
                if not buf:
                    break
            be_writer.write(buf)
            up += len(buf)

        await be_writer.drain()

    return up, down


# ── Terminated connection handler ─────────────────────────────────────────────

async def handle_terminated(
    tls: TLSTerminator,
    sni: str,
    cfg: Config,
    route_index: RouteIndex,
    src: str,
    started: float,
) -> None:
    up = down = 0
    try:
        # Read HTTP request headers
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = await tls.read(4096, timeout=cfg.read_timeout)
            if not chunk:
                return
            buf += chunk
            if len(buf) > 65536:
                logger.warning(f"[{src}] HTTP headers too large — dropped")
                return

        sep = buf.index(b"\r\n\r\n")
        headers_data = buf[: sep + 4]
        leftover = buf[sep + 4:]

        # Parse path for routing (strip query string)
        first_line = headers_data.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
        req_parts = first_line.split(" ", 2)
        method = req_parts[0] if req_parts else "GET"
        full_path = req_parts[1] if len(req_parts) > 1 else "/"
        path_only = full_path.split("?")[0]

        result = find_route(sni, path_only, route_index)
        if result is None:
            logger.warning(f"[{src}] SNI={sni} {method} {full_path} — no route, dropped")
            await tls.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            return

        path_prefix, backend = result
        if not backend.enabled:
            logger.warning(f"[{src}] SNI={sni} {method} {full_path} — route disabled")
            await tls.write(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            return

        logger.info(f"[{src}] SNI={sni} {method} {full_path:<30} → {backend.name} ({backend.host}:{backend.port})")

        new_headers = rewrite_http_request(
            headers_data, path_prefix, backend.strip_path, backend.host, backend.port
        )

        # Connect to backend
        try:
            if backend.backend_ssl:
                be_ctx = ssl.create_default_context()
                be_ctx.check_hostname = False
                be_ctx.verify_mode = ssl.CERT_NONE
                be_reader, be_writer = await asyncio.wait_for(
                    asyncio.open_connection(backend.host, backend.port, ssl=be_ctx),
                    timeout=cfg.connect_timeout,
                )
            else:
                be_reader, be_writer = await asyncio.wait_for(
                    asyncio.open_connection(backend.host, backend.port),
                    timeout=cfg.connect_timeout,
                )
        except asyncio.TimeoutError:
            logger.error(f"[{src}] connect timeout → {backend.name}")
            await tls.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            return
        except OSError as exc:
            logger.error(f"[{src}] cannot connect → {backend.name}: {exc}")
            await tls.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            return

        be_writer.write(new_headers)
        await be_writer.drain()
        up += len(new_headers)

        if backend.rewrite_paths and path_prefix:
            # HTTP/1.1 loop with response rewriting
            add_up, add_down = await _http_proxy_loop(
                tls, be_reader, be_writer, path_prefix, backend, leftover
            )
            up += add_up
            down += add_down
        else:
            # Simple bidirectional pipe
            if leftover:
                be_writer.write(leftover)
                await be_writer.drain()

            async def client_to_be() -> None:
                nonlocal up
                try:
                    while True:
                        data = await tls.read(65536)
                        if not data:
                            break
                        be_writer.write(data)
                        await be_writer.drain()
                        up += len(data)
                except Exception:
                    pass
                finally:
                    try:
                        be_writer.close()
                        await be_writer.wait_closed()
                    except Exception:
                        pass

            async def be_to_client() -> None:
                nonlocal down
                try:
                    while True:
                        data = await be_reader.read(65536)
                        if not data:
                            break
                        await tls.write(data)
                        down += len(data)
                except Exception:
                    pass

            await asyncio.gather(client_to_be(), be_to_client())

        elapsed = time.monotonic() - started
        logger.info(
            f"[{src}] closed  SNI={sni} {method} {full_path} → {backend.name} "
            f"↑{_fmt_bytes(up)} ↓{_fmt_bytes(down)} {elapsed:.1f}s"
        )

    except Exception as exc:
        logger.exception(f"[{src}] terminated handler error: {exc}")
    finally:
        await tls.close()


# ── Connection handler ────────────────────────────────────────────────────────

async def handle_connection(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    cfg: Config,
    route_index: RouteIndex,
    ssl_ctx: Optional[ssl.SSLContext],
) -> None:
    peer = client_writer.get_extra_info("peername") or ("?", 0)
    src = f"{peer[0]}:{peer[1]}"
    started = time.monotonic()

    try:
        try:
            initial = await asyncio.wait_for(client_reader.read(4096), timeout=cfg.read_timeout)
        except asyncio.TimeoutError:
            logger.warning(f"[{src}] timeout waiting for initial data — dropped")
            return

        if not initial:
            return

        sni = extract_sni(initial)
        if not sni:
            logger.warning(f"[{src}] no SNI — dropped")
            return

        # ── Path-based routing: terminate TLS ─────────────────────────────────
        if hostname_needs_termination(sni, route_index):
            if not ssl_ctx:
                logger.error(f"[{src}] SNI={sni} needs TLS termination but no cert configured")
                return
            tls = TLSTerminator(ssl_ctx, client_reader, client_writer)
            try:
                await tls.do_handshake(initial)
            except Exception as exc:
                logger.warning(f"[{src}] TLS handshake failed for {sni}: {exc}")
                return
            await handle_terminated(tls, sni, cfg, route_index, src, started)
            return

        # ── Hostname-only routing: passthrough ────────────────────────────────
        result = find_route(sni, "", route_index)
        if result is None:
            logger.warning(f"[{src}] SNI={sni} — no route configured, dropped")
            return
        _, backend = result

        if not backend.enabled:
            logger.warning(f"[{src}] SNI={sni} — route disabled, dropped")
            return

        logger.info(f"[{src}] SNI={sni:<35} → {backend.name} ({backend.host}:{backend.port})")

        try:
            be_reader, be_writer = await asyncio.wait_for(
                asyncio.open_connection(backend.host, backend.port),
                timeout=cfg.connect_timeout,
            )
        except asyncio.TimeoutError:
            logger.error(f"[{src}] connect timeout → {backend.name} ({backend.host}:{backend.port})")
            return
        except OSError as exc:
            logger.error(f"[{src}] cannot connect → {backend.name} ({backend.host}:{backend.port}): {exc}")
            return

        be_writer.write(initial)
        await be_writer.drain()

        up, down = await asyncio.gather(
            pipe(client_reader, be_writer, f"{src}→{backend.name}"),
            pipe(be_reader, client_writer, f"{backend.name}→{src}"),
        )

        elapsed = time.monotonic() - started
        logger.info(
            f"[{src}] closed  SNI={sni} → {backend.name} "
            f"↑{_fmt_bytes(up)} ↓{_fmt_bytes(down)} {elapsed:.1f}s"
        )

    except Exception as exc:
        logger.exception(f"[{src}] unhandled error: {exc}")
    finally:
        try:
            client_writer.close()
            await client_writer.wait_closed()
        except Exception:
            pass


def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n}{unit}"
        n //= 1024
    return f"{n}TB"


# ── Admin web UI ──────────────────────────────────────────────────────────────

ADMIN_HTML = """\
<!DOCTYPE html>
<html lang="nl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SNI Proxy — Routes</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, sans-serif; background: #f0f2f5; padding: 2rem; color: #222; }
  h1 { margin-bottom: 1.5rem; font-size: 1.4rem; font-weight: 600; }
  table { width: 100%; max-width: 900px; border-collapse: collapse; background: #fff;
          border-radius: 10px; overflow: hidden; box-shadow: 0 1px 6px rgba(0,0,0,.1); }
  th { background: #f7f7f7; padding: .7rem 1.2rem; text-align: left; font-size: .8rem;
       color: #888; text-transform: uppercase; letter-spacing: .05em; border-bottom: 1px solid #eee; }
  td { padding: .85rem 1.2rem; border-top: 1px solid #f0f0f0; font-size: .9rem; vertical-align: middle; }
  tr:first-child td { border-top: none; }
  .host { font-family: monospace; font-size: .88rem; }
  .backend { color: #777; font-size: .82rem; font-family: monospace; }
  .badge { display: inline-block; padding: .2rem .65rem; border-radius: 20px;
           font-size: .78rem; font-weight: 600; }
  .badge-on  { background: #dcf5e7; color: #1a7a40; }
  .badge-off { background: #fde8e8; color: #b91c1c; }
  .badge-mode { background: #e0e7ff; color: #3730a3; margin-left: .3rem; }
  .toggle { position: relative; display: inline-block; width: 46px; height: 26px; }
  .toggle input { opacity: 0; width: 0; height: 0; }
  .slider { position: absolute; cursor: pointer; inset: 0; background: #d1d5db;
            border-radius: 26px; transition: background .2s; }
  .slider:before { position: absolute; content: ""; height: 20px; width: 20px;
                   left: 3px; bottom: 3px; background: #fff; border-radius: 50%;
                   transition: transform .2s; box-shadow: 0 1px 3px rgba(0,0,0,.2); }
  input:checked + .slider { background: #22c55e; }
  input:checked + .slider:before { transform: translateX(20px); }
  input:disabled + .slider { opacity: .5; cursor: wait; }
  .msg { margin-top: 1rem; max-width: 900px; padding: .7rem 1rem; border-radius: 8px;
         font-size: .88rem; display: none; }
  .msg-ok  { background: #dcf5e7; color: #166534; }
  .msg-err { background: #fde8e8; color: #991b1b; }
</style>
</head>
<body>
<h1>SNI Proxy &mdash; Routes</h1>
<table>
  <thead>
    <tr>
      <th>Route</th>
      <th>Backend</th>
      <th>Status</th>
      <th>Aan / Uit</th>
    </tr>
  </thead>
  <tbody id="tbody">
    <tr><td colspan="4" style="color:#aaa;padding:1.5rem">Laden&hellip;</td></tr>
  </tbody>
</table>
<div id="msg" class="msg"></div>

<script>
async function load() {
  try {
    const r = await fetch('/api/routes');
    const routes = await r.json();
    document.getElementById('tbody').innerHTML = routes.map(rt => `
      <tr>
        <td class="host">${esc(rt.route_key)}</td>
        <td class="backend">
          ${esc(rt.name)} &rarr; ${esc(rt.host)}:${rt.port}
          ${rt.backend_ssl ? '<span class="badge badge-mode">HTTPS</span>' : ''}
          ${rt.route_key.includes('/') ? '<span class="badge badge-mode">pad</span>' : ''}
        </td>
        <td><span class="badge ${rt.enabled ? 'badge-on' : 'badge-off'}">${rt.enabled ? 'Aan' : 'Uit'}</span></td>
        <td>
          <label class="toggle" title="${rt.enabled ? 'Klik om uit te zetten' : 'Klik om aan te zetten'}">
            <input type="checkbox" ${rt.enabled ? 'checked' : ''}
                   onchange='toggle(${JSON.stringify(rt.route_key)}, this)'>
            <span class="slider"></span>
          </label>
        </td>
      </tr>
    `).join('');
  } catch (e) {
    showMsg('Kon routes niet laden: ' + e, false);
  }
}

async function toggle(routeKey, el) {
  el.disabled = true;
  try {
    const r = await fetch('/api/routes/' + encodeURIComponent(routeKey) + '/toggle', {method: 'POST'});
    if (!r.ok) {
      el.checked = !el.checked;
      showMsg('Fout bij omschakelen van ' + routeKey, false);
      return;
    }
    const data = await r.json();
    showMsg(`${routeKey} is nu ${data.enabled ? 'ingeschakeld' : 'uitgeschakeld'}.`, true);
    await load();
  } catch (e) {
    el.checked = !el.checked;
    showMsg('Netwerkfout: ' + e, false);
  } finally {
    el.disabled = false;
  }
}

function showMsg(text, ok) {
  const el = document.getElementById('msg');
  el.textContent = text;
  el.className = 'msg ' + (ok ? 'msg-ok' : 'msg-err');
  el.style.display = 'block';
  clearTimeout(el._t);
  el._t = setTimeout(() => { el.style.display = 'none'; }, 4000);
}

function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

load();
</script>
</body>
</html>
"""


async def handle_admin(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    proxy_server: "ProxyServer",
) -> None:
    try:
        request_line = await asyncio.wait_for(reader.readline(), timeout=10)
        if not request_line:
            return
        parts = request_line.decode("utf-8", errors="replace").strip().split()
        if len(parts) < 2:
            return
        method, path = parts[0].upper(), parts[1].split("?")[0]

        content_length = 0
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=10)
            if not line or line in (b"\r\n", b"\n"):
                break
            if line.lower().startswith(b"content-length:"):
                try:
                    content_length = int(line.split(b":")[1].strip())
                except ValueError:
                    pass
        if content_length > 0:
            await asyncio.wait_for(reader.read(min(content_length, 4096)), timeout=10)

        def respond(status: int, content_type: str, body: bytes) -> None:
            status_text = {200: "OK", 400: "Bad Request", 404: "Not Found"}.get(status, "")
            writer.write((
                f"HTTP/1.1 {status} {status_text}\r\n"
                f"Content-Type: {content_type}\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode() + body)

        if method == "GET" and path == "/":
            respond(200, "text/html; charset=utf-8", ADMIN_HTML.encode("utf-8"))

        elif method == "GET" and path == "/api/routes":
            routes = [
                {
                    "route_key": k,
                    "host": b.host, "port": b.port, "name": b.name,
                    "enabled": b.enabled, "backend_ssl": b.backend_ssl,
                }
                for k, b in proxy_server.cfg.tls_routes.items()
            ]
            respond(200, "application/json", json.dumps(routes).encode())

        elif method == "POST" and path.startswith("/api/routes/") and path.endswith("/toggle"):
            segments = path.strip("/").split("/")
            # segments: ['api', 'routes', '<route_key>', 'toggle']
            if len(segments) >= 4 and segments[0] == "api" and segments[1] == "routes":
                route_key = urllib.parse.unquote("/".join(segments[2:-1]))
                backend = proxy_server.cfg.tls_routes.get(route_key)
                if backend is None:
                    respond(404, "application/json", json.dumps({"error": "route not found"}).encode())
                else:
                    backend.enabled = not backend.enabled
                    proxy_server._route_index = build_route_index(proxy_server.cfg.tls_routes)
                    save_config(proxy_server.cfg, proxy_server.config_path)
                    state = "ingeschakeld" if backend.enabled else "uitgeschakeld"
                    logger.info(f"Route {route_key} {state} via admin UI")
                    respond(200, "application/json", json.dumps({"route_key": route_key, "enabled": backend.enabled}).encode())
            else:
                respond(400, "application/json", json.dumps({"error": "bad request"}).encode())

        else:
            respond(404, "text/plain", b"Not found")

        await writer.drain()

    except Exception as exc:
        logger.debug(f"Admin handler error: {exc}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


# ── Server ────────────────────────────────────────────────────────────────────

class ProxyServer:
    def __init__(self, config_path: Path) -> None:
        self.config_path = config_path
        self.cfg = load_config(config_path)
        self._route_index = build_route_index(self.cfg.tls_routes)
        self._ssl_ctx = self._load_ssl_ctx()

    def _load_ssl_ctx(self) -> Optional[ssl.SSLContext]:
        if self.cfg.tls_cert and self.cfg.tls_key:
            return build_ssl_ctx(self.cfg.tls_cert, self.cfg.tls_key)
        return None

    def reload(self) -> None:
        logger.info("SIGHUP received — reloading config")
        try:
            self.cfg = load_config(self.config_path)
            self._route_index = build_route_index(self.cfg.tls_routes)
            self._ssl_ctx = self._load_ssl_ctx()
            log_config(self.cfg)
        except Exception as exc:
            logger.error(f"Config reload failed: {exc} — keeping old config")

    async def run(self) -> None:
        log_config(self.cfg)

        def handler(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> asyncio.Task:
            return asyncio.create_task(
                handle_connection(r, w, self.cfg, self._route_index, self._ssl_ctx)
            )

        def admin_handler(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> asyncio.Task:
            return asyncio.create_task(handle_admin(r, w, self))

        self._servers: list[asyncio.Server] = []
        for port in self.cfg.listen_ports:
            srv = await asyncio.start_server(handler, self.cfg.listen_host, port)
            self._servers.append(srv)
            addrs = [str(s.getsockname()) for s in srv.sockets or []]
            logger.info(f"Proxy listening on {', '.join(addrs)}")

        admin_srv = await asyncio.start_server(admin_handler, self.cfg.admin_host, self.cfg.admin_port)
        self._servers.append(admin_srv)
        logger.info(f"Admin UI listening on http://{self.cfg.admin_host}:{self.cfg.admin_port}/")

        loop = asyncio.get_running_loop()
        loop.add_signal_handler(signal.SIGHUP, self.reload)
        loop.add_signal_handler(signal.SIGTERM, self._stop_all)

        await asyncio.gather(*(srv.serve_forever() for srv in self._servers))

    def _stop_all(self) -> None:
        for srv in getattr(self, "_servers", []):
            srv.close()


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    if "--help" in sys.argv or "-h" in sys.argv:
        print(__doc__)
        sys.exit(0)

    config_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("config.json")

    server = ProxyServer(config_path)
    try:
        asyncio.run(server.run())
    except KeyboardInterrupt:
        logger.info("Proxy stopped (SIGINT)")


if __name__ == "__main__":
    main()
