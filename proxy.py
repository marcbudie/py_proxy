#!/usr/bin/env python3
"""
TCP SNI Proxy — routes HTTPS by SNI hostname (no TLS termination).

Usage:
  python3 proxy.py [config.json]
  python3 proxy.py --help

Signals:
  SIGHUP  — reload config without restarting
"""

import asyncio
import json
import logging
import os
import signal
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
    "admin_port": 8080,
}


@dataclass
class Backend:
    host: str
    port: int
    name: str
    enabled: bool = True


@dataclass
class Config:
    listen_host: str
    listen_ports: list[int]
    tls_routes: dict[str, Backend]
    connect_timeout: int
    read_timeout: int
    admin_host: str = "0.0.0.0"
    admin_port: int = 8080


def _parse_backend(d: dict) -> Backend:
    return Backend(
        host=d["host"],
        port=d["port"],
        name=d["name"],
        enabled=d.get("enabled", True),
    )


def load_config(path: Path) -> Config:
    if path.exists():
        raw = json.loads(path.read_text())
        logger.info(f"Config loaded from {path}")
    else:
        raw = DEFAULT_CONFIG
        path.write_text(json.dumps(DEFAULT_CONFIG, indent=2))
        logger.info(f"No config found — wrote default to {path}")

    # Accept both old "listen_port" (int) and new "listen_ports" (list)
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
        admin_port=raw.get("admin_port", 8080),
    )


def save_config(cfg: Config, path: Path) -> None:
    data = {
        "listen_host": cfg.listen_host,
        "listen_ports": cfg.listen_ports,
        "tls_routes": {
            h: {"host": b.host, "port": b.port, "name": b.name, "enabled": b.enabled}
            for h, b in cfg.tls_routes.items()
        },
        "connect_timeout": cfg.connect_timeout,
        "read_timeout": cfg.read_timeout,
        "admin_host": cfg.admin_host,
        "admin_port": cfg.admin_port,
    }
    path.write_text(json.dumps(data, indent=2))


def log_config(cfg: Config) -> None:
    ports = ", ".join(str(p) for p in cfg.listen_ports)
    logger.info(f"Listen: {cfg.listen_host}  ports: {ports}")
    logger.info("TLS routes:")
    for host, be in cfg.tls_routes.items():
        state = "ON " if be.enabled else "OFF"
        logger.info(f"  [{state}] {host:<35} → {be.name} ({be.host}:{be.port})")


# ── SNI extraction ────────────────────────────────────────────────────────────

def _is_tls(data: bytes) -> bool:
    return (
        len(data) >= 3
        and data[0] == 0x16
        and data[1] == 0x03
        and data[2] in (0x00, 0x01, 0x02, 0x03, 0x04)
    )


def extract_sni(data: bytes) -> Optional[str]:
    """
    Parse TLS ClientHello and return the SNI hostname, or None.
    Does NOT terminate TLS — the raw bytes are forwarded untouched afterward.
    """
    try:
        if not _is_tls(data) or len(data) < 6:
            return None

        pos = 5                         # skip TLS record header (5 bytes)
        if data[pos] != 0x01:           # must be ClientHello
            return None
        pos += 4                        # skip handshake type (1) + length (3)
        pos += 2                        # skip client_version
        pos += 32                       # skip random

        if pos >= len(data):
            return None
        pos += 1 + data[pos]            # skip session_id

        if pos + 2 > len(data):
            return None
        cs_len = struct.unpack("!H", data[pos: pos + 2])[0]
        pos += 2 + cs_len               # skip cipher_suites

        if pos >= len(data):
            return None
        pos += 1 + data[pos]            # skip compression_methods

        if pos + 2 > len(data):
            return None
        ext_end = pos + 2 + struct.unpack("!H", data[pos: pos + 2])[0]
        pos += 2

        while pos + 4 <= ext_end and pos + 4 <= len(data):
            ext_type = struct.unpack("!H", data[pos: pos + 2])[0]
            ext_len  = struct.unpack("!H", data[pos + 2: pos + 4])[0]
            pos += 4

            if ext_type == 0x0000:      # server_name (SNI)
                if pos + 5 <= len(data):
                    name_type = data[pos + 2]
                    name_len  = struct.unpack("!H", data[pos + 3: pos + 5])[0]
                    if name_type == 0x00 and pos + 5 + name_len <= len(data):
                        return data[pos + 5: pos + 5 + name_len].decode("ascii")
            pos += ext_len

        return None

    except Exception:
        return None


# ── Bidirectional pipe ────────────────────────────────────────────────────────

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
        logger.debug(f"  pipe {label}: {exc}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
    return total


# ── Connection handler ────────────────────────────────────────────────────────

async def handle_connection(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    cfg: Config,
) -> None:
    peer = client_writer.get_extra_info("peername") or ("?", 0)
    src = f"{peer[0]}:{peer[1]}"
    started = time.monotonic()

    try:
        try:
            initial = await asyncio.wait_for(
                client_reader.read(4096),
                timeout=cfg.read_timeout,
            )
        except asyncio.TimeoutError:
            logger.warning(f"[{src}] timeout waiting for initial data — dropped")
            return

        if not initial:
            return

        sni = extract_sni(initial)
        if not sni:
            logger.warning(f"[{src}] no SNI — dropped")
            return

        backend = cfg.tls_routes.get(sni.lower())
        if not backend:
            logger.warning(f"[{src}] SNI={sni} — no route configured, dropped")
            return

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
            pipe(be_reader,     client_writer, f"{backend.name}→{src}"),
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
  table { width: 100%; max-width: 750px; border-collapse: collapse; background: #fff;
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
  /* Toggle switch */
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
  .msg { margin-top: 1rem; max-width: 750px; padding: .7rem 1rem; border-radius: 8px;
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
      <th>Hostname</th>
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
      <tr id="row-${CSS.escape(rt.hostname)}">
        <td class="host">${esc(rt.hostname)}</td>
        <td class="backend">${esc(rt.name)} &rarr; ${esc(rt.host)}:${rt.port}</td>
        <td><span class="badge ${rt.enabled ? 'badge-on' : 'badge-off'}">${rt.enabled ? 'Aan' : 'Uit'}</span></td>
        <td>
          <label class="toggle" title="${rt.enabled ? 'Klik om uit te zetten' : 'Klik om aan te zetten'}">
            <input type="checkbox" ${rt.enabled ? 'checked' : ''}
                   onchange="toggle(${JSON.stringify(rt.hostname)}, this)">
            <span class="slider"></span>
          </label>
        </td>
      </tr>
    `).join('');
  } catch (e) {
    showMsg('Kon routes niet laden: ' + e, false);
  }
}

async function toggle(hostname, el) {
  el.disabled = true;
  try {
    const r = await fetch('/api/routes/' + encodeURIComponent(hostname) + '/toggle', {method: 'POST'});
    if (!r.ok) {
      el.checked = !el.checked;
      showMsg('Fout bij omschakelen van ' + hostname, false);
      return;
    }
    const data = await r.json();
    showMsg(`${hostname} is nu ${data.enabled ? 'ingeschakeld' : 'uitgeschakeld'}.`, true);
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
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
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
        # Read request line
        request_line = await asyncio.wait_for(reader.readline(), timeout=10)
        if not request_line:
            return

        parts = request_line.decode("utf-8", errors="replace").strip().split()
        if len(parts) < 2:
            return
        method, path = parts[0].upper(), parts[1]

        # Strip query string
        path = path.split("?")[0]

        # Read headers
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

        # Read body (if any)
        if content_length > 0:
            await asyncio.wait_for(reader.read(min(content_length, 4096)), timeout=10)

        def respond(status: int, content_type: str, body: bytes) -> None:
            status_text = {200: "OK", 400: "Bad Request", 404: "Not Found", 405: "Method Not Allowed"}.get(status, "")
            header = (
                f"HTTP/1.1 {status} {status_text}\r\n"
                f"Content-Type: {content_type}\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode()
            writer.write(header + body)

        # ── GET / ─────────────────────────────────────────────────────────────
        if method == "GET" and path == "/":
            respond(200, "text/html; charset=utf-8", ADMIN_HTML.encode("utf-8"))

        # ── GET /api/routes ───────────────────────────────────────────────────
        elif method == "GET" and path == "/api/routes":
            routes = [
                {
                    "hostname": h,
                    "host": b.host,
                    "port": b.port,
                    "name": b.name,
                    "enabled": b.enabled,
                }
                for h, b in proxy_server.cfg.tls_routes.items()
            ]
            respond(200, "application/json", json.dumps(routes).encode())

        # ── POST /api/routes/<hostname>/toggle ────────────────────────────────
        elif method == "POST" and path.startswith("/api/routes/") and path.endswith("/toggle"):
            segments = path.strip("/").split("/")
            # segments: ['api', 'routes', '<hostname>', 'toggle']
            if len(segments) == 4 and segments[0] == "api" and segments[1] == "routes":
                hostname = urllib.parse.unquote(segments[2])
                backend = proxy_server.cfg.tls_routes.get(hostname)
                if backend is None:
                    respond(404, "application/json", json.dumps({"error": "route not found"}).encode())
                else:
                    backend.enabled = not backend.enabled
                    save_config(proxy_server.cfg, proxy_server.config_path)
                    state = "ingeschakeld" if backend.enabled else "uitgeschakeld"
                    logger.info(f"Route {hostname} {state} via admin UI")
                    respond(200, "application/json", json.dumps({"hostname": hostname, "enabled": backend.enabled}).encode())
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

    def reload(self) -> None:
        logger.info("SIGHUP received — reloading config")
        try:
            self.cfg = load_config(self.config_path)
            log_config(self.cfg)
        except Exception as exc:
            logger.error(f"Config reload failed: {exc} — keeping old config")

    async def run(self) -> None:
        log_config(self.cfg)

        def handler(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> asyncio.Task:
            return asyncio.create_task(handle_connection(r, w, self.cfg))

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

    default_ports = DEFAULT_CONFIG.get("listen_ports", [443])
    if os.geteuid() != 0 and any(p < 1024 for p in default_ports):
        logger.warning(
            "Running as non-root on a privileged port may fail. "
            "Use: sudo setcap cap_net_bind_service+ep $(which python3)"
        )

    server = ProxyServer(config_path)
    try:
        asyncio.run(server.run())
    except KeyboardInterrupt:
        logger.info("Proxy stopped (SIGINT)")


if __name__ == "__main__":
    main()
