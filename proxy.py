#!/usr/bin/env python3
"""
TCP SNI Proxy — routes HTTPS by SNI hostname without TLS termination.
Admin UI served over HTTPS (port 9443) with one-time-code authentication.

Usage:
  python3 proxy.py [config.json]
  python3 proxy.py --help

Signals:
  SIGHUP  — reload config without restarting
"""

import asyncio
import html
import json
import logging
import secrets
import signal
import smtplib
import ssl
import struct
import sys
import time
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
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


# ── Auth constants ────────────────────────────────────────────────────────────

OTP_TTL        = 300    # OTP geldig voor 5 minuten
SESSION_TTL    = 1800   # sessie geldig voor 30 minuten
CODE_COOLDOWN  = 60     # minimaal 60s tussen code-aanvragen
MAX_OTP_ATTEMPTS = 10   # max foutieve pogingen voor code ongeldig wordt

# In-memory auth state (asyncio single-threaded — geen locks nodig)
_otp_store: dict[str, tuple[float, bool]] = {}   # code → (expires_at, used)
_sessions:  dict[str, float]              = {}   # token → expires_at
_last_code_ts: float                      = 0.0  # tijdstip laatste code-aanvraag
_verify_attempts: int                     = 0    # foutieve verify-pogingen sinds laatste code


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
    "admin_port": 9443,
    "email": {
        "gmail_user": "",
        "gmail_app_password": "",
        "to": "marc.budie@gmail.com",
    },
}


@dataclass
class EmailConfig:
    gmail_user: str = ""
    gmail_app_password: str = ""
    to: str = "marc.budie@gmail.com"


@dataclass
class Backend:
    host: str
    port: int
    name: str
    enabled: bool = True
    tls_cert: Optional[str] = None
    tls_key:  Optional[str] = None


@dataclass
class Config:
    listen_host: str
    listen_ports: list[int]
    tls_routes: dict[str, Backend]
    connect_timeout: int
    read_timeout: int
    admin_host: str = "0.0.0.0"
    admin_port: int = 9443
    tls_cert: Optional[str] = None   # wildcard cert voor foutpagina's
    tls_key:  Optional[str] = None
    email: EmailConfig = None
    tcp_routes: dict = None           # listen_port (int) → Backend

    def __post_init__(self):
        if self.email is None:
            self.email = EmailConfig()
        if self.tcp_routes is None:
            self.tcp_routes = {}


def _parse_backend(d: dict) -> Backend:
    return Backend(
        host=d["host"],
        port=d["port"],
        name=d["name"],
        enabled=d.get("enabled", True),
        tls_cert=d.get("tls_cert"),
        tls_key=d.get("tls_key"),
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

    ec = raw.get("email", {})
    email_cfg = EmailConfig(
        gmail_user=ec.get("gmail_user", ""),
        gmail_app_password=ec.get("gmail_app_password", ""),
        to=ec.get("to", "marc.budie@gmail.com"),
    )

    return Config(
        listen_host=raw.get("listen_host", "0.0.0.0"),
        listen_ports=raw_ports,
        tls_routes={h: _parse_backend(b) for h, b in raw.get("tls_routes", {}).items()},
        connect_timeout=raw.get("connect_timeout", 10),
        read_timeout=raw.get("read_timeout", 5),
        admin_host=raw.get("admin_host", "0.0.0.0"),
        admin_port=raw.get("admin_port", 9443),
        tls_cert=raw.get("tls_cert"),
        tls_key=raw.get("tls_key"),
        email=email_cfg,
        tcp_routes={int(p): _parse_backend(b) for p, b in raw.get("tcp_routes", {}).items()},
    )


def save_config(cfg: Config, path: Path) -> None:
    data = {
        "listen_host": cfg.listen_host,
        "listen_ports": cfg.listen_ports,
        "tls_routes": {
            h: {k: v for k, v in {
                "host": b.host, "port": b.port, "name": b.name, "enabled": b.enabled,
                "tls_cert": b.tls_cert, "tls_key": b.tls_key,
            }.items() if v is not None or k in ("host", "port", "name", "enabled")}
            for h, b in cfg.tls_routes.items()
        },
        "connect_timeout": cfg.connect_timeout,
        "read_timeout": cfg.read_timeout,
        "admin_host": cfg.admin_host,
        "admin_port": cfg.admin_port,
        "tls_cert": cfg.tls_cert,
        "tls_key": cfg.tls_key,
        "email": {
            "gmail_user": cfg.email.gmail_user,
            "gmail_app_password": cfg.email.gmail_app_password,
            "to": cfg.email.to,
        },
        "tcp_routes": {
            str(p): {"host": b.host, "port": b.port, "name": b.name, "enabled": b.enabled}
            for p, b in cfg.tcp_routes.items()
        },
    }
    path.write_text(json.dumps(data, indent=2))


def log_config(cfg: Config) -> None:
    ports = ", ".join(str(p) for p in cfg.listen_ports)
    logger.info(f"Listen: {cfg.listen_host}  ports: {ports}")
    logger.info("TLS routes:")
    for host, be in cfg.tls_routes.items():
        state = "ON " if be.enabled else "OFF"
        logger.info(f"  [{state}] {host:<35} → {be.name} ({be.host}:{be.port})")
    if cfg.tcp_routes:
        logger.info("TCP routes:")
        for listen_port, be in cfg.tcp_routes.items():
            state = "ON " if be.enabled else "OFF"
            logger.info(f"  [{state}] :{listen_port:<34} → {be.name} ({be.host}:{be.port})")


# ── SNI extraction ────────────────────────────────────────────────────────────

def _is_tls(data: bytes) -> bool:
    return (
        len(data) >= 3
        and data[0] == 0x16
        and data[1] == 0x03
        and data[2] in (0x00, 0x01, 0x02, 0x03, 0x04)
    )


def extract_sni(data: bytes) -> Optional[str]:
    """Parse TLS ClientHello and return the SNI hostname, or None."""
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
        logger.debug(f"pipe {label}: {exc}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
    return total


# ── TLS error page ────────────────────────────────────────────────────────────

ERROR_HTML = """\
<!DOCTYPE html>
<html lang="nl">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Route uitgeschakeld</title>
<style>
  body {{ font-family: system-ui, sans-serif; background: #f0f2f5; display: flex;
         align-items: center; justify-content: center; min-height: 100vh; margin: 0; }}
  .card {{ background: #fff; border-radius: 12px; padding: 2.5rem 3rem; text-align: center;
           box-shadow: 0 2px 12px rgba(0,0,0,.1); max-width: 420px; }}
  h1 {{ font-size: 1.3rem; color: #b91c1c; margin-bottom: .75rem; }}
  p  {{ color: #555; font-size: .95rem; line-height: 1.5; }}
  code {{ background: #f3f4f6; padding: .15rem .4rem; border-radius: 4px; font-size: .9rem; }}
</style>
</head>
<body>
<div class="card">
  <h1>Route uitgeschakeld</h1>
  <p><code>{hostname}</code> is momenteel uitgeschakeld.<br>
  Schakel de route in via de proxy admin UI.</p>
</div>
</body>
</html>
"""


async def send_tls_error_page(
    initial_data: bytes,
    sni: str,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    ssl_ctx: ssl.SSLContext,
    admin_host: str,
) -> None:
    """Terminate TLS and send an HTML error page, then close."""
    incoming = ssl.MemoryBIO()
    outgoing = ssl.MemoryBIO()
    ssl_obj = ssl_ctx.wrap_bio(incoming, outgoing, server_side=True)
    incoming.write(initial_data)

    async def flush() -> None:
        if outgoing.pending:
            writer.write(outgoing.read())
            await writer.drain()

    try:
        while True:
            try:
                ssl_obj.do_handshake()
                break
            except ssl.SSLWantReadError:
                await flush()
                more = await asyncio.wait_for(reader.read(16384), timeout=10)
                if not more:
                    return
                incoming.write(more)
            except ssl.SSLWantWriteError:
                await flush()
        await flush()
    except Exception:
        return

    body = ERROR_HTML.format(hostname=html.escape(sni), admin_host=html.escape(admin_host)).encode("utf-8")
    response = (
        f"HTTP/1.1 503 Service Unavailable\r\n"
        f"Content-Type: text/html; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body
    try:
        ssl_obj.write(response)
        await flush()
    except Exception:
        pass


# ── Auth helpers ──────────────────────────────────────────────────────────────

def _cleanup_expired() -> None:
    now = time.time()
    expired_otps = [c for c, (exp, _) in _otp_store.items() if now > exp]
    for c in expired_otps:
        del _otp_store[c]
    expired_sessions = [t for t, exp in _sessions.items() if now > exp]
    for t in expired_sessions:
        del _sessions[t]


def _check_session(token: Optional[str]) -> bool:
    if not token:
        return False
    exp = _sessions.get(token)
    if exp is None or time.time() > exp:
        if token in _sessions:
            del _sessions[token]
        return False
    return True


def _create_session() -> str:
    token = secrets.token_hex(32)
    _sessions[token] = time.time() + SESSION_TTL
    return token


def _generate_otp() -> str:
    """Maak een 6-cijferige code en sla hem op."""
    global _verify_attempts
    _cleanup_expired()
    _verify_attempts = 0
    code = f"{secrets.randbelow(1_000_000):06d}"
    _otp_store[code] = (time.time() + OTP_TTL, False)
    return code


def _verify_otp(code: str) -> bool:
    """Geeft True als de code klopt, geldig is en nog niet gebruikt is.
    Na MAX_OTP_ATTEMPTS foutieve pogingen wordt de code ongeldig gemaakt."""
    global _verify_attempts
    entry = _otp_store.get(code)
    if entry is None:
        _verify_attempts += 1
        if _verify_attempts >= MAX_OTP_ATTEMPTS:
            _otp_store.clear()
            logger.warning("Max OTP-pogingen bereikt — code ongeldig gemaakt")
        return False
    expires_at, used = entry
    if used or time.time() > expires_at:
        del _otp_store[code]
        return False
    _otp_store[code] = (expires_at, True)  # markeer als gebruikt
    _verify_attempts = 0
    return True


# ── Email ─────────────────────────────────────────────────────────────────────

def _send_otp_email_sync(code: str, email_cfg: EmailConfig) -> None:
    """Verstuurt de OTP-code via Gmail (blocking — in executor aanroepen)."""
    now_str = datetime.now(timezone.utc).strftime("%d-%m-%Y %H:%M UTC")
    html = f"""\
<html>
<body style="font-family:system-ui,sans-serif;color:#1a1a1a;background:#f0f2f5;
             display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0">
  <div style="background:#fff;border-radius:12px;padding:2.5rem 3rem;text-align:center;
              box-shadow:0 2px 12px rgba(0,0,0,.1);max-width:400px">
    <h2 style="color:#6366f1;margin-bottom:1rem">SNI Proxy — Inlogcode</h2>
    <p style="color:#555;font-size:.95rem;margin-bottom:1.5rem">
      Gebruik de onderstaande code om in te loggen op de proxy admin UI.<br>
      De code is <strong>5 minuten geldig</strong> en kan maar <strong>één keer</strong> worden gebruikt.
    </p>
    <div style="font-size:2.5rem;font-weight:700;letter-spacing:.3em;color:#111;
                background:#f3f4f6;border-radius:8px;padding:.75rem 1.5rem;display:inline-block">
      {code}
    </div>
    <p style="color:#aaa;font-size:.78rem;margin-top:1.5rem">{now_str}</p>
  </div>
</body>
</html>"""

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "SNI Proxy — Inlogcode"
    msg["From"]    = email_cfg.gmail_user
    msg["To"]      = email_cfg.to
    msg.attach(MIMEText(html, "html"))

    ctx = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=ctx) as server:
        server.login(email_cfg.gmail_user, email_cfg.gmail_app_password)
        server.sendmail(email_cfg.gmail_user, email_cfg.to, msg.as_string())


async def send_otp_email(code: str, email_cfg: EmailConfig) -> None:
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, _send_otp_email_sync, code, email_cfg)


# ── Connection handler ────────────────────────────────────────────────────────

async def handle_connection(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    cfg: Config,
    server: "ProxyServer",
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
            return

        if not initial:
            return

        sni = extract_sni(initial)
        if not sni:
            return

        backend = cfg.tls_routes.get(sni.lower())
        if not backend:
            logger.warning(f"[{src}] SNI={sni} — no route configured, dropped")
            return

        if not backend.enabled:
            ssl_ctx = server._ssl_ctx_for(backend)
            if ssl_ctx:
                logger.info(f"[{src}] SNI={sni} — route disabled, sending error page")
                await send_tls_error_page(
                    initial, sni, client_reader, client_writer, ssl_ctx,
                    f"{cfg.admin_host}:{cfg.admin_port}",
                )
            else:
                logger.info(f"[{src}] SNI={sni} — route disabled, dropped")
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


# ── Admin HTML pages ──────────────────────────────────────────────────────────

LOGO_SVG = """\
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 40 40">
  <rect width="40" height="40" rx="9" fill="#4f46e5"/>
  <circle cx="8" cy="20" r="3.5" fill="white"/>
  <circle cx="20" cy="20" r="4.5" fill="white"/>
  <circle cx="33" cy="10" r="3" fill="white" opacity=".9"/>
  <circle cx="33" cy="20" r="3" fill="white" opacity=".9"/>
  <circle cx="33" cy="30" r="3" fill="white" opacity=".9"/>
  <line x1="11.5" y1="20" x2="15.5" y2="20" stroke="white" stroke-width="2" stroke-linecap="round"/>
  <line x1="24.5" y1="20" x2="30" y2="20" stroke="white" stroke-width="1.8" stroke-linecap="round"/>
  <line x1="23.5" y1="17" x2="30" y2="11" stroke="white" stroke-width="1.8" stroke-linecap="round"/>
  <line x1="23.5" y1="23" x2="30" y2="29" stroke="white" stroke-width="1.8" stroke-linecap="round"/>
</svg>"""

_LOGO_INLINE = """\
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 40 40" width="{size}" height="{size}" style="flex-shrink:0">
  <rect width="40" height="40" rx="9" fill="#4f46e5"/>
  <circle cx="8" cy="20" r="3.5" fill="white"/>
  <circle cx="20" cy="20" r="4.5" fill="white"/>
  <circle cx="33" cy="10" r="3" fill="white" opacity=".9"/>
  <circle cx="33" cy="20" r="3" fill="white" opacity=".9"/>
  <circle cx="33" cy="30" r="3" fill="white" opacity=".9"/>
  <line x1="11.5" y1="20" x2="15.5" y2="20" stroke="white" stroke-width="2" stroke-linecap="round"/>
  <line x1="24.5" y1="20" x2="30" y2="20" stroke="white" stroke-width="1.8" stroke-linecap="round"/>
  <line x1="23.5" y1="17" x2="30" y2="11" stroke="white" stroke-width="1.8" stroke-linecap="round"/>
  <line x1="23.5" y1="23" x2="30" y2="29" stroke="white" stroke-width="1.8" stroke-linecap="round"/>
</svg>"""

_LOGO_36 = _LOGO_INLINE.format(size=36)
_LOGO_32 = _LOGO_INLINE.format(size=32)

LOGIN_HTML = """\
<!DOCTYPE html>
<html lang="nl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SNI Proxy — Inloggen</title>
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, sans-serif; background: #f0f2f5;
         display: flex; align-items: center; justify-content: center;
         min-height: 100vh; color: #222; }
  .card { background: #fff; border-radius: 12px; padding: 2.5rem 3rem;
          box-shadow: 0 2px 12px rgba(0,0,0,.12); width: 360px; text-align: center; }
  h1 { font-size: 1.3rem; font-weight: 600; margin-bottom: .4rem; }
  .sub { color: #888; font-size: .88rem; margin-bottom: 2rem; }
  .step { display: none; }
  .step.active { display: block; }
  button { width: 100%; padding: .65rem; border: none; border-radius: 8px;
           background: #6366f1; color: #fff; font-size: .95rem; cursor: pointer;
           font-weight: 500; transition: background .15s; }
  button:hover { background: #4f46e5; }
  button:disabled { background: #a5b4fc; cursor: wait; }
  input[type=text] { width: 100%; padding: .6rem .8rem; border: 1px solid #d1d5db;
                     border-radius: 8px; font-size: 1.1rem; text-align: center;
                     letter-spacing: .25em; margin-bottom: 1rem; }
  input[type=text]:focus { outline: 2px solid #6366f1; border-color: transparent; }
  .msg { margin-top: 1rem; padding: .6rem .9rem; border-radius: 8px;
         font-size: .85rem; display: none; }
  .msg-ok  { background: #dcf5e7; color: #166534; display: block; }
  .msg-err { background: #fde8e8; color: #991b1b; display: block; }
  .hint { color: #9ca3af; font-size: .8rem; margin-top: 1.5rem; }
  @media (max-width: 400px) {
    .card { padding: 2rem 1.25rem; width: 100%; }
  }
</style>
</head>
<body>
<div class="card">
  <div style="display:flex;align-items:center;justify-content:center;gap:.6rem;margin-bottom:.4rem">
    """ + _LOGO_36 + """
    <h1>SNI Proxy</h1>
  </div>
  <p class="sub">Admin toegang vereist</p>

  <!-- Stap 1: vraag code aan -->
  <div id="step1" class="step active">
    <button id="btnSend" onclick="requestCode()">Stuur inlogcode naar e-mail</button>
    <p class="hint">Er wordt een eenmalige code naar het beheerders-e-mailadres verstuurd.</p>
    <div id="msg1" class="msg"></div>
  </div>

  <!-- Stap 2: voer code in -->
  <div id="step2" class="step">
    <p style="color:#555;font-size:.88rem;margin-bottom:1.25rem">
      Er is een 6-cijferige code naar je e-mail verstuurd.<br>
      De code is 5 minuten geldig.
    </p>
    <input id="codeInput" type="text" maxlength="6" placeholder="000000"
           oninput="this.value=this.value.replace(/[^0-9]/g,'')"
           onkeydown="if(event.key==='Enter')verifyCode()">
    <button id="btnVerify" onclick="verifyCode()">Inloggen</button>
    <p class="hint" style="cursor:pointer" onclick="backToStep1()">
      &larr; Nieuwe code aanvragen
    </p>
    <div id="msg2" class="msg"></div>
  </div>
</div>

<script>
function show(id) {
  document.getElementById('step1').classList.remove('active');
  document.getElementById('step2').classList.remove('active');
  document.getElementById(id).classList.add('active');
}
function setMsg(id, text, ok) {
  const el = document.getElementById(id);
  el.textContent = text;
  el.className = 'msg ' + (ok ? 'msg-ok' : 'msg-err');
}

async function requestCode() {
  const btn = document.getElementById('btnSend');
  btn.disabled = true;
  btn.textContent = 'Versturen\u2026';
  setMsg('msg1', '', false);
  try {
    const r = await fetch('/api/auth/request-code', {method: 'POST'});
    const d = await r.json();
    if (!r.ok) { setMsg('msg1', d.error || 'Fout bij versturen.', false); return; }
    show('step2');
    document.getElementById('codeInput').focus();
  } catch (e) {
    setMsg('msg1', 'Netwerkfout: ' + e, false);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Stuur inlogcode naar e-mail';
  }
}

async function verifyCode() {
  const code = document.getElementById('codeInput').value.trim();
  if (code.length !== 6) { setMsg('msg2', 'Voer een 6-cijferige code in.', false); return; }
  const btn = document.getElementById('btnVerify');
  btn.disabled = true;
  btn.textContent = 'Controleren\u2026';
  try {
    const r = await fetch('/api/auth/verify', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({code}),
    });
    const d = await r.json();
    if (!r.ok) { setMsg('msg2', d.error || 'Ongeldige code.', false); return; }
    window.location.href = '/';
  } catch (e) {
    setMsg('msg2', 'Netwerkfout: ' + e, false);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Inloggen';
  }
}

function backToStep1() {
  document.getElementById('codeInput').value = '';
  setMsg('msg2', '', false);
  show('step1');
}
</script>
</body>
</html>
"""


ADMIN_HTML = """\
<!DOCTYPE html>
<html lang="nl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SNI Proxy — Routes</title>
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, sans-serif; background: #f0f2f5; padding: 2rem; color: #222; }
  .topbar { display: flex; align-items: center; justify-content: space-between;
            max-width: 800px; margin-bottom: 1.5rem; }
  h1 { font-size: 1.4rem; font-weight: 600; }
  .btn-logout { background: none; border: 1px solid #d1d5db; color: #555;
                border-radius: 6px; padding: .3rem .8rem; font-size: .82rem;
                cursor: pointer; }
  .btn-logout:hover { background: #f3f4f6; }
  table { width: 100%; max-width: 800px; border-collapse: collapse; background: #fff;
          border-radius: 10px; overflow: hidden; box-shadow: 0 1px 6px rgba(0,0,0,.1); }
  th { background: #f7f7f7; padding: .7rem 1.2rem; text-align: left; font-size: .8rem;
       color: #888; text-transform: uppercase; letter-spacing: .05em; border-bottom: 1px solid #eee; }
  td { padding: .75rem 1.2rem; border-top: 1px solid #f0f0f0; font-size: .9rem; vertical-align: middle; }
  tr:first-child td { border-top: none; }
  .host { font-family: monospace; font-size: .88rem; }
  .backend { color: #777; font-size: .82rem; font-family: monospace; }
  .badge { display: inline-block; padding: .2rem .65rem; border-radius: 20px; font-size: .78rem; font-weight: 600; }
  .badge-on  { background: #dcf5e7; color: #1a7a40; }
  .badge-off { background: #fde8e8; color: #b91c1c; }
  .toggle { position: relative; display: inline-block; width: 46px; height: 26px; }
  .toggle input { opacity: 0; width: 0; height: 0; }
  .slider { position: absolute; cursor: pointer; inset: 0; background: #d1d5db; border-radius: 26px; transition: background .2s; }
  .slider:before { position: absolute; content: ""; height: 20px; width: 20px; left: 3px; bottom: 3px;
                   background: #fff; border-radius: 50%; transition: transform .2s; box-shadow: 0 1px 3px rgba(0,0,0,.2); }
  input:checked + .slider { background: #22c55e; }
  input:checked + .slider:before { transform: translateX(20px); }
  input:disabled + .slider { opacity: .5; cursor: wait; }
  .btn-del { background: none; border: 1px solid #fca5a5; color: #dc2626; border-radius: 6px;
             padding: .25rem .6rem; font-size: .8rem; cursor: pointer; }
  .btn-del:hover { background: #fef2f2; }
  .add-card { margin-top: 1.5rem; max-width: 800px; background: #fff; border-radius: 10px;
              padding: 1.25rem 1.5rem; box-shadow: 0 1px 6px rgba(0,0,0,.1); }
  .add-card h2 { font-size: 1rem; font-weight: 600; margin-bottom: 1rem; }
  .fields { display: grid; grid-template-columns: 2fr 2fr 1fr 1fr; gap: .6rem; }
  .fields input { padding: .45rem .7rem; border: 1px solid #d1d5db; border-radius: 6px;
                  font-size: .88rem; width: 100%; }
  .fields input:focus { outline: 2px solid #6366f1; border-color: transparent; }
  .btn-add { margin-top: .75rem; padding: .5rem 1.2rem; background: #6366f1; color: #fff;
             border: none; border-radius: 6px; font-size: .9rem; cursor: pointer; }
  .btn-add:hover { background: #4f46e5; }
  .msg { margin-top: 1rem; max-width: 800px; padding: .7rem 1rem; border-radius: 8px;
         font-size: .88rem; display: none; }
  .msg-ok  { background: #dcf5e7; color: #166534; }
  .msg-err { background: #fde8e8; color: #991b1b; }
  @media (max-width: 640px) {
    body { padding: 1rem; }
    h1 { font-size: 1.2rem; }
    table { background: transparent; box-shadow: none; border-radius: 0; }
    table thead { display: none; }
    table, tbody { display: block; }
    tr { display: block; background: #fff; border-radius: 10px; margin-bottom: .75rem;
         padding: .75rem 1rem; box-shadow: 0 1px 4px rgba(0,0,0,.08); }
    td { display: block; border: none !important; padding: .15rem 0; }
    td:nth-child(3) { display: none; }
    td:nth-child(4), td:nth-child(5) { display: inline-block; vertical-align: middle;
                                        margin-right: .5rem; margin-top: .5rem; }
    .add-card { padding: 1rem; }
    .fields { grid-template-columns: 1fr; }
    .btn-add { width: 100%; }
  }
</style>
</head>
<body>
<div class="topbar">
  <div style="display:flex;align-items:center;gap:.6rem">
    """ + _LOGO_32 + """
    <h1>SNI Proxy</h1>
  </div>
  <button class="btn-logout" onclick="logout()">Uitloggen</button>
</div>
<table>
  <thead>
    <tr>
      <th>Hostname</th>
      <th>Backend</th>
      <th>Status</th>
      <th>Aan / Uit</th>
      <th></th>
    </tr>
  </thead>
  <tbody id="tbody">
    <tr><td colspan="5" style="color:#aaa;padding:1.5rem">Laden&hellip;</td></tr>
  </tbody>
</table>

<h2 style="max-width:800px;margin-top:2rem;margin-bottom:.75rem;font-size:1rem;font-weight:600;color:#555">TCP routes</h2>
<table>
  <thead>
    <tr>
      <th>Luisterpoort</th>
      <th>Backend</th>
      <th>Status</th>
      <th>Aan / Uit</th>
    </tr>
  </thead>
  <tbody id="tcp-tbody">
    <tr><td colspan="4" style="color:#aaa;padding:1.5rem">Laden&hellip;</td></tr>
  </tbody>
</table>

<div class="add-card">
  <h2>Route toevoegen</h2>
  <div class="fields">
    <input id="f-hostname" placeholder="hostname (bijv. app.budie.eu)" autocomplete="off">
    <input id="f-host"     placeholder="backend host (bijv. 192.168.2.10)" autocomplete="off">
    <input id="f-port"     placeholder="poort" type="number" min="1" max="65535" autocomplete="off">
    <input id="f-name"     placeholder="label" autocomplete="off">
  </div>
  <button class="btn-add" onclick="addRoute()">Toevoegen</button>
</div>

<div id="msg" class="msg"></div>

<script>
async function load() {
  try {
    const r = await fetch('/api/routes');
    if (r.status === 401) { window.location.href = '/login'; return; }
    const routes = await r.json();
    document.getElementById('tbody').innerHTML = routes.length ? routes.map(rt => `
      <tr>
        <td class="host">${esc(rt.hostname)}</td>
        <td class="backend">${esc(rt.name)} &rarr; ${esc(rt.host)}:${rt.port}</td>
        <td><span class="badge ${rt.enabled ? 'badge-on' : 'badge-off'}">${rt.enabled ? 'Aan' : 'Uit'}</span></td>
        <td>
          <label class="toggle" title="${rt.enabled ? 'Klik om uit te zetten' : 'Klik om aan te zetten'}">
            <input type="checkbox" ${rt.enabled ? 'checked' : ''}
                   onchange='toggle(${JSON.stringify(rt.hostname)}, this)'>
            <span class="slider"></span>
          </label>
        </td>
        <td><button class="btn-del" onclick='remove(${JSON.stringify(rt.hostname)})'>Verwijder</button></td>
      </tr>
    `).join('') : '<tr><td colspan="5" style="color:#aaa;padding:1.5rem">Geen routes geconfigureerd.</td></tr>';
  } catch (e) {
    showMsg('Kon routes niet laden: ' + e, false);
  }
}

async function toggle(hostname, el) {
  el.disabled = true;
  try {
    const r = await fetch('/api/routes/' + encodeURIComponent(hostname) + '/toggle', {method: 'POST'});
    if (r.status === 401) { window.location.href = '/login'; return; }
    if (!r.ok) { el.checked = !el.checked; showMsg('Fout bij omschakelen van ' + hostname, false); return; }
    const data = await r.json();
    showMsg(`${hostname} is nu ${data.enabled ? 'ingeschakeld' : 'uitgeschakeld'}.`, true);
    await load();
  } catch (e) {
    el.checked = !el.checked;
    showMsg('Netwerkfout: ' + e, false);
  } finally { el.disabled = false; }
}

async function remove(hostname) {
  if (!confirm(`Route "${hostname}" verwijderen?`)) return;
  try {
    const r = await fetch('/api/routes/' + encodeURIComponent(hostname), {method: 'DELETE'});
    if (r.status === 401) { window.location.href = '/login'; return; }
    if (!r.ok) { showMsg('Verwijderen mislukt.', false); return; }
    showMsg(`${hostname} verwijderd.`, true);
    await load();
  } catch (e) { showMsg('Netwerkfout: ' + e, false); }
}

async function addRoute() {
  const hostname = document.getElementById('f-hostname').value.trim().toLowerCase();
  const host     = document.getElementById('f-host').value.trim();
  const port     = parseInt(document.getElementById('f-port').value, 10);
  const name     = document.getElementById('f-name').value.trim();
  if (!hostname || !host || !port || !name) { showMsg('Vul alle velden in.', false); return; }
  try {
    const r = await fetch('/api/routes', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({hostname, host, port, name}),
    });
    if (r.status === 401) { window.location.href = '/login'; return; }
    if (!r.ok) {
      const d = await r.json().catch(() => ({}));
      showMsg(d.error || 'Toevoegen mislukt.', false);
      return;
    }
    showMsg(`${hostname} toegevoegd.`, true);
    document.getElementById('f-hostname').value = '';
    document.getElementById('f-host').value = '';
    document.getElementById('f-port').value = '';
    document.getElementById('f-name').value = '';
    await load();
  } catch (e) { showMsg('Netwerkfout: ' + e, false); }
}

async function loadTcp() {
  try {
    const r = await fetch('/api/tcp-routes');
    if (r.status === 401) { window.location.href = '/login'; return; }
    const routes = await r.json();
    document.getElementById('tcp-tbody').innerHTML = routes.length ? routes.map(rt => `
      <tr>
        <td class="host">:${rt.listen_port}</td>
        <td class="backend">${esc(rt.name)} &rarr; ${esc(rt.host)}:${rt.port}</td>
        <td><span class="badge ${rt.enabled ? 'badge-on' : 'badge-off'}">${rt.enabled ? 'Aan' : 'Uit'}</span></td>
        <td>
          <label class="toggle" title="${rt.enabled ? 'Klik om uit te zetten' : 'Klik om aan te zetten'}">
            <input type="checkbox" ${rt.enabled ? 'checked' : ''}
                   onchange='toggleTcp(${rt.listen_port}, this)'>
            <span class="slider"></span>
          </label>
        </td>
      </tr>
    `).join('') : '<tr><td colspan="4" style="color:#aaa;padding:1.5rem">Geen TCP routes geconfigureerd.</td></tr>';
  } catch (e) { showMsg('Kon TCP routes niet laden: ' + e, false); }
}

async function toggleTcp(port, el) {
  el.disabled = true;
  try {
    const r = await fetch('/api/tcp-routes/' + port + '/toggle', {method: 'POST'});
    if (r.status === 401) { window.location.href = '/login'; return; }
    if (!r.ok) { el.checked = !el.checked; showMsg('Fout bij omschakelen van poort ' + port, false); return; }
    const data = await r.json();
    showMsg(`TCP :${port} is nu ${data.enabled ? 'ingeschakeld' : 'uitgeschakeld'}.`, true);
    await loadTcp();
  } catch (e) {
    el.checked = !el.checked;
    showMsg('Netwerkfout: ' + e, false);
  } finally { el.disabled = false; }
}

async function logout() {
  await fetch('/api/auth/logout', {method: 'POST'});
  window.location.href = '/login';
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
loadTcp();
</script>
</body>
</html>
"""


# ── Admin web UI handler ──────────────────────────────────────────────────────

def _parse_cookies(cookie_header: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for part in cookie_header.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            cookies[k.strip()] = v.strip()
    return cookies


async def handle_tcp_connection(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    backend: Backend,
    cfg: Config,
) -> None:
    src = writer.get_extra_info("peername")
    try:
        if not backend.enabled:
            logger.info(f"[{src}] TCP:{backend.name} — route disabled, dropped")
            return
        logger.info(f"[{src}] TCP → {backend.name} ({backend.host}:{backend.port})")
        try:
            be_reader, be_writer = await asyncio.wait_for(
                asyncio.open_connection(backend.host, backend.port),
                timeout=cfg.connect_timeout,
            )
        except asyncio.TimeoutError:
            logger.error(f"[{src}] TCP connect timeout → {backend.name}")
            return
        except OSError as exc:
            logger.error(f"[{src}] TCP connect failed → {backend.name}: {exc}")
            return
        await asyncio.gather(
            pipe(reader, be_writer, f"{src}→{backend.name}"),
            pipe(be_reader, writer, f"{backend.name}→{src}"),
        )
    except Exception as exc:
        logger.exception(f"[{src}] TCP unhandled: {exc}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def handle_admin(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    proxy_server: "ProxyServer",
) -> None:
    try:
      while True:
        try:
            request_line = await asyncio.wait_for(reader.readline(), timeout=30)
        except asyncio.TimeoutError:
            break
        if not request_line:
            break
        parts = request_line.decode("utf-8", errors="replace").strip().split()
        if len(parts) < 2:
            return
        method, path = parts[0].upper(), parts[1].split("?")[0]

        headers_raw: dict[str, str] = {}
        content_length = 0
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=10)
            if not line or line in (b"\r\n", b"\n"):
                break
            if b":" in line:
                k, v = line.split(b":", 1)
                headers_raw[k.strip().lower().decode()] = v.strip().decode()
            if line.lower().startswith(b"content-length:"):
                try:
                    content_length = int(line.split(b":")[1].strip())
                except ValueError:
                    pass

        body = b""
        if content_length > 0:
            body = await asyncio.wait_for(reader.read(min(content_length, 4096)), timeout=10)

        cookies = _parse_cookies(headers_raw.get("cookie", ""))
        session_token = cookies.get("proxy_session")
        authed = _check_session(session_token)

        STATUS_TEXTS = {
            200: "OK", 302: "Found", 400: "Bad Request",
            401: "Unauthorized", 404: "Not Found",
            429: "Too Many Requests", 500: "Internal Server Error",
        }

        def respond(
            status: int,
            content_type: str,
            body_bytes: bytes,
            extra_headers: Optional[list[tuple[str, str]]] = None,
        ) -> None:
            lines = [
                f"HTTP/1.1 {status} {STATUS_TEXTS.get(status, '')}",
                f"Content-Type: {content_type}",
                f"Content-Length: {len(body_bytes)}",
                "Connection: keep-alive",
            ]
            if extra_headers:
                lines.extend(f"{k}: {v}" for k, v in extra_headers)
            writer.write(("\r\n".join(lines) + "\r\n\r\n").encode() + body_bytes)

        def redirect(location: str) -> None:
            writer.write((
                f"HTTP/1.1 302 Found\r\n"
                f"Location: {location}\r\n"
                f"Content-Length: 0\r\n"
                f"Connection: close\r\n\r\n"
            ).encode())

        def json_resp(status: int, data: dict, extra_headers: Optional[list[tuple[str, str]]] = None) -> None:
            respond(status, "application/json", json.dumps(data).encode(), extra_headers)

        # ── Auth endpoints (geen sessie vereist) ──────────────────────────────

        if method == "GET" and path == "/favicon.svg":
            respond(200, "image/svg+xml", LOGO_SVG.encode())

        elif method == "GET" and path == "/login":
            respond(200, "text/html; charset=utf-8", LOGIN_HTML.encode("utf-8"))

        elif method == "POST" and path == "/api/auth/request-code":
            global _last_code_ts
            now = time.time()
            remaining = CODE_COOLDOWN - (now - _last_code_ts)
            if remaining > 0:
                json_resp(429, {"error": f"Wacht nog {int(remaining)+1} seconden voor een nieuwe code."})
            elif not proxy_server.cfg.email.gmail_user:
                json_resp(500, {"error": "E-mail niet geconfigureerd in config.json."})
            else:
                code = _generate_otp()
                _last_code_ts = now
                try:
                    await send_otp_email(code, proxy_server.cfg.email)
                    logger.info(f"OTP-code verstuurd naar {proxy_server.cfg.email.to}")
                    json_resp(200, {"ok": True})
                except Exception as exc:
                    logger.error(f"E-mail versturen mislukt: {exc}")
                    json_resp(500, {"error": "E-mail versturen mislukt. Controleer de e-mailconfiguratie."})

        elif method == "POST" and path == "/api/auth/verify":
            try:
                data = json.loads(body)
                code = str(data.get("code", "")).strip()
            except Exception:
                json_resp(400, {"error": "Ongeldige invoer."})
            else:
                if _verify_otp(code):
                    token = _create_session()
                    cookie = (
                        f"proxy_session={token}; "
                        f"Max-Age={SESSION_TTL}; "
                        f"Path=/; HttpOnly; Secure; SameSite=Strict"
                    )
                    logger.info("Succesvolle inlog via OTP")
                    json_resp(200, {"ok": True}, [("Set-Cookie", cookie)])
                else:
                    json_resp(401, {"error": "Ongeldige of verlopen code."})

        elif method == "POST" and path == "/api/auth/logout":
            if session_token and session_token in _sessions:
                del _sessions[session_token]
            clear_cookie = "proxy_session=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Strict"
            json_resp(200, {"ok": True}, [("Set-Cookie", clear_cookie)])

        # ── Beveiligde routes (sessie vereist) ────────────────────────────────

        elif method == "GET" and path == "/":
            if not authed:
                redirect("/login")
            else:
                respond(200, "text/html; charset=utf-8", ADMIN_HTML.encode("utf-8"))

        elif not authed:
            json_resp(401, {"error": "Niet ingelogd."})

        elif method == "GET" and path == "/api/routes":
            routes = [
                {"hostname": h, "host": b.host, "port": b.port, "name": b.name, "enabled": b.enabled}
                for h, b in proxy_server.cfg.tls_routes.items()
            ]
            respond(200, "application/json", json.dumps(routes).encode())

        elif method == "POST" and path == "/api/routes":
            try:
                data = json.loads(body)
                hostname = data["hostname"].strip().lower()
                host     = data["host"].strip()
                port     = int(data["port"])
                name     = data["name"].strip()
                if not hostname or not host or not name or not (1 <= port <= 65535):
                    raise ValueError("invalid fields")
            except Exception:
                json_resp(400, {"error": "Ongeldige invoer."})
            else:
                if hostname in proxy_server.cfg.tls_routes:
                    json_resp(400, {"error": "Hostname bestaat al."})
                else:
                    proxy_server.cfg.tls_routes[hostname] = Backend(host=host, port=port, name=name)
                    save_config(proxy_server.cfg, proxy_server.config_path)
                    logger.info(f"Route {hostname} → {name} ({host}:{port}) toegevoegd via admin UI")
                    json_resp(200, {"hostname": hostname})

        elif method == "DELETE" and path.startswith("/api/routes/"):
            hostname = urllib.parse.unquote(path[len("/api/routes/"):])
            if hostname not in proxy_server.cfg.tls_routes:
                json_resp(404, {"error": "Route niet gevonden."})
            else:
                del proxy_server.cfg.tls_routes[hostname]
                save_config(proxy_server.cfg, proxy_server.config_path)
                logger.info(f"Route {hostname} verwijderd via admin UI")
                json_resp(200, {"hostname": hostname})

        elif method == "POST" and path.startswith("/api/routes/") and path.endswith("/toggle"):
            segments = path.strip("/").split("/")
            if len(segments) == 4 and segments[0] == "api" and segments[1] == "routes":
                hostname = urllib.parse.unquote(segments[2])
                backend  = proxy_server.cfg.tls_routes.get(hostname)
                if backend is None:
                    json_resp(404, {"error": "Route niet gevonden."})
                else:
                    backend.enabled = not backend.enabled
                    save_config(proxy_server.cfg, proxy_server.config_path)
                    state = "ingeschakeld" if backend.enabled else "uitgeschakeld"
                    logger.info(f"Route {hostname} {state} via admin UI")
                    json_resp(200, {"hostname": hostname, "enabled": backend.enabled})
            else:
                json_resp(400, {"error": "Ongeldig verzoek."})

        elif method == "GET" and path == "/api/tcp-routes":
            routes = [
                {"listen_port": p, "host": b.host, "port": b.port, "name": b.name, "enabled": b.enabled}
                for p, b in proxy_server.cfg.tcp_routes.items()
            ]
            respond(200, "application/json", json.dumps(routes).encode())

        elif method == "POST" and path.startswith("/api/tcp-routes/") and path.endswith("/toggle"):
            try:
                listen_port = int(path.strip("/").split("/")[2])
            except (ValueError, IndexError):
                json_resp(400, {"error": "Ongeldige poort."})
            else:
                backend = proxy_server.cfg.tcp_routes.get(listen_port)
                if backend is None:
                    json_resp(404, {"error": "TCP route niet gevonden."})
                else:
                    backend.enabled = not backend.enabled
                    save_config(proxy_server.cfg, proxy_server.config_path)
                    state = "ingeschakeld" if backend.enabled else "uitgeschakeld"
                    logger.info(f"TCP route :{listen_port} {state} via admin UI")
                    json_resp(200, {"listen_port": listen_port, "enabled": backend.enabled})

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
        self._ssl_ctxs: dict[tuple[str, str], ssl.SSLContext] = self._load_ssl_ctxs()

    def _load_ssl_ctxs(self) -> dict[tuple[str, str], ssl.SSLContext]:
        ctxs: dict[tuple[str, str], ssl.SSLContext] = {}
        pairs: list[tuple[str, str]] = []
        if self.cfg.tls_cert and self.cfg.tls_key:
            pairs.append((self.cfg.tls_cert, self.cfg.tls_key))
        for be in self.cfg.tls_routes.values():
            if be.tls_cert and be.tls_key:
                pairs.append((be.tls_cert, be.tls_key))
        for cert, key in pairs:
            if (cert, key) in ctxs:
                continue
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(cert, key)
                ctxs[(cert, key)] = ctx
                logger.info(f"TLS cert geladen: {cert}")
            except Exception as exc:
                logger.error(f"Kon TLS cert niet laden ({cert}): {exc}")
        return ctxs

    def _ssl_ctx_for(self, backend: Backend) -> Optional[ssl.SSLContext]:
        if backend.tls_cert and backend.tls_key:
            return self._ssl_ctxs.get((backend.tls_cert, backend.tls_key))
        if self.cfg.tls_cert and self.cfg.tls_key:
            return self._ssl_ctxs.get((self.cfg.tls_cert, self.cfg.tls_key))
        return None

    def _make_admin_ssl_ctx(self) -> Optional[ssl.SSLContext]:
        cert = self.cfg.tls_cert
        key  = self.cfg.tls_key
        if not cert or not key:
            return None
        ctx = self._ssl_ctxs.get((cert, key))
        if ctx:
            return ctx
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert, key)
            self._ssl_ctxs[(cert, key)] = ctx
            return ctx
        except Exception as exc:
            logger.error(f"Kon admin TLS cert niet laden: {exc}")
            return None

    def reload(self) -> None:
        logger.info("SIGHUP received — reloading config")
        try:
            self.cfg = load_config(self.config_path)
            self._ssl_ctxs = self._load_ssl_ctxs()
            log_config(self.cfg)
        except Exception as exc:
            logger.error(f"Config reload failed: {exc} — keeping old config")

    async def run(self) -> None:
        log_config(self.cfg)

        def handler(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> asyncio.Task:
            return asyncio.create_task(handle_connection(r, w, self.cfg, self))

        def admin_handler(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> asyncio.Task:
            return asyncio.create_task(handle_admin(r, w, self))

        self._servers: list[asyncio.Server] = []
        for port in self.cfg.listen_ports:
            srv = await asyncio.start_server(handler, self.cfg.listen_host, port)
            self._servers.append(srv)
            addrs = [str(s.getsockname()) for s in srv.sockets or []]
            logger.info(f"Proxy listening on {', '.join(addrs)}")

        for listen_port, backend in self.cfg.tcp_routes.items():
            def tcp_handler(r, w, b=backend):
                return asyncio.create_task(handle_tcp_connection(r, w, b, self.cfg))
            srv = await asyncio.start_server(tcp_handler, self.cfg.listen_host, listen_port)
            self._servers.append(srv)
            logger.info(f"TCP route :{listen_port} → {backend.name} ({backend.host}:{backend.port})")

        admin_ssl = self._make_admin_ssl_ctx()
        if not admin_ssl:
            logger.critical(
                "Admin UI kan niet starten: geen geldig TLS-cert geconfigureerd. "
                "Stel tls_cert en tls_key in in config.json."
            )
            raise SystemExit(1)
        admin_srv = await asyncio.start_server(
            admin_handler, self.cfg.admin_host, self.cfg.admin_port, ssl=admin_ssl
        )
        logger.info(f"Admin UI listening on https://{self.cfg.admin_host}:{self.cfg.admin_port}/ (TLS)")
        self._servers.append(admin_srv)

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
