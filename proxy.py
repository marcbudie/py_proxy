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
import base64
import hashlib
import hmac
import html
import json
import logging
import os
import re
import secrets
import signal
import smtplib
import ssl
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Optional
import io
try:
    import segno
    _SEGNO_OK = True
except ImportError:
    _SEGNO_OK = False

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
_last_code_ts: float                      = 0.0  # tijdstip laatste code-aanvraag (globaal)
_code_ts_per_ip: dict[str, float]         = {}   # ip → tijdstip laatste code-aanvraag
_verify_attempts: int                     = 0    # foutieve verify-pogingen sinds laatste code

# Alert-cooldowns (voorkomt spam bij aanhoudende backend-problemen)
_alert_cooldowns: dict[str, float] = {}  # backend_name → tijdstip laatste alert
_ALERT_COOLDOWN = 300  # maximaal één alert per 5 minuten per backend

# Runtime statistieken (in-memory, gereset bij herstart)
_stats: dict = {
    "active_tls": 0,   # actieve TLS verbindingen op dit moment
    "active_tcp": 0,   # actieve TCP verbindingen op dit moment
    "tls_ok":  {},     # sni → aantal succesvolle verbindingen
    "tls_rej": {},     # sni → aantal geweigerd (route uitgeschakeld)
    "tls_unknown": 0,  # verbindingen zonder bekende SNI
    "tcp_ok":  {},     # name → aantal succesvolle verbindingen
    "tcp_rej": {},     # name → aantal geweigerd (route uitgeschakeld)
    "since":   0.0,    # timestamp proxy-start (gezet in ProxyServer.__init__)
}


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
    "telegram": {
        "bot_token": "",
        "allowed_chat_ids": [],
    },
}


@dataclass
class EmailConfig:
    gmail_user: str = ""
    gmail_app_password: str = ""
    to: str = "marc.budie@gmail.com"


@dataclass
class TelegramConfig:
    bot_token: str = ""
    allowed_chat_ids: list = None   # type: ignore[assignment]
    mini_app_url: str = ""

    def __post_init__(self):
        if self.allowed_chat_ids is None:
            self.allowed_chat_ids = []


@dataclass
class Backend:
    host: str
    port: int
    name: str
    enabled: bool = True
    tls_cert: Optional[str] = None
    tls_key:  Optional[str] = None
    notify:        bool = False          # stuur Telegram-bericht bij elke verbinding
    tls_terminate: bool = False          # termineer TLS en stuur plain HTTP door naar backend
    auto_disable_minutes: int = 0       # minuten tot auto-uitschakelen na inschakelen (0 = nooit)
    enabled_until: Optional[float] = field(default=None, repr=False)  # runtime, niet opgeslagen


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
    telegram: TelegramConfig = None
    totp_secret: str = ""             # base32 TOTP secret; leeg = TOTP niet actief

    def __post_init__(self):
        if self.email is None:
            self.email = EmailConfig()
        if self.tcp_routes is None:
            self.tcp_routes = {}
        if self.telegram is None:
            self.telegram = TelegramConfig()


def _parse_backend(d: dict) -> Backend:
    return Backend(
        host=d["host"],
        port=d["port"],
        name=d["name"],
        enabled=d.get("enabled", True),
        tls_cert=d.get("tls_cert"),
        tls_key=d.get("tls_key"),
        notify=d.get("notify", False),
        tls_terminate=d.get("tls_terminate", False),
        auto_disable_minutes=int(d.get("auto_disable_minutes", 0)),
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

    tc = raw.get("telegram", {})
    telegram_cfg = TelegramConfig(
        bot_token=tc.get("bot_token", ""),
        allowed_chat_ids=tc.get("allowed_chat_ids", []),
        mini_app_url=tc.get("mini_app_url", ""),
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
        telegram=telegram_cfg,
        totp_secret=raw.get("totp_secret", ""),
    )


def save_config(cfg: Config, path: Path) -> None:
    data = {
        "listen_host": cfg.listen_host,
        "listen_ports": cfg.listen_ports,
        "tls_routes": {
            h: {k: v for k, v in {
                "host": b.host, "port": b.port, "name": b.name, "enabled": b.enabled,
                "tls_cert": b.tls_cert, "tls_key": b.tls_key,
                "notify": b.notify or None,
                "tls_terminate": b.tls_terminate or None,
                "auto_disable_minutes": b.auto_disable_minutes or None,
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
            str(p): {k: v for k, v in {
                "host": b.host, "port": b.port, "name": b.name, "enabled": b.enabled,
                "auto_disable_minutes": b.auto_disable_minutes or None,
            }.items() if v is not None or k in ("host", "port", "name", "enabled")}
            for p, b in cfg.tcp_routes.items()
        },
        "telegram": {
            "bot_token": cfg.telegram.bot_token,
            "allowed_chat_ids": cfg.telegram.allowed_chat_ids,
            "mini_app_url": cfg.telegram.mini_app_url,
        },
        "totp_secret": cfg.totp_secret,
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
            if pos + ext_len > len(data):
                return None
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


def _rewrite_host_header(data: bytes, new_host: str) -> bytes:
    """Vervang de Host-header in het eerste HTTP-verzoek (eenmalig)."""
    return re.sub(
        rb'(?i)Host:[ \t]*[^\r\n]+\r\n',
        b'Host: ' + new_host.encode('ascii') + b'\r\n',
        data, count=1,
    )


async def _tls_terminate_and_pipe(
    initial: bytes,
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    ssl_ctx: ssl.SSLContext,
    be_reader: asyncio.StreamReader,
    be_writer: asyncio.StreamWriter,
    backend_host: str = "",
) -> tuple[int, int]:
    """Termineer TLS aan de client-kant en pip plain bytes naar/van de backend.
    Als backend_host opgegeven is, wordt de Host-header herschreven."""
    incoming = ssl.MemoryBIO()
    outgoing = ssl.MemoryBIO()
    ssl_obj = ssl_ctx.wrap_bio(incoming, outgoing, server_side=True)
    incoming.write(initial)

    async def flush_to_client() -> None:
        if outgoing.pending:
            client_writer.write(outgoing.read())
            await client_writer.drain()

    # TLS handshake
    try:
        while True:
            try:
                ssl_obj.do_handshake()
                break
            except ssl.SSLWantReadError:
                await flush_to_client()
                more = await asyncio.wait_for(client_reader.read(16384), timeout=10)
                if not more:
                    return 0, 0
                incoming.write(more)
            except ssl.SSLWantWriteError:
                await flush_to_client()
        await flush_to_client()
    except Exception:
        return 0, 0

    # Bidirectioneel pipen via event-loop tasks
    c_to_b = 0
    b_to_c = 0
    _host_rewritten = False

    def _maybe_rewrite(data: bytes) -> bytes:
        nonlocal _host_rewritten
        if backend_host and not _host_rewritten:
            _host_rewritten = True
            return _rewrite_host_header(data, backend_host)
        return data

    # Na de handshake kan er al application data in de MemoryBIO zitten
    # (browser stuurt HTTP-request vaak in hetzelfde TLS-blok als Finished).
    # Drain dit nu direct naar de backend.
    while True:
        try:
            chunk = ssl_obj.read(16384)
            if not chunk:
                break
            be_writer.write(_maybe_rewrite(chunk))
            c_to_b += len(chunk)
        except (ssl.SSLWantReadError, ssl.SSLZeroReturnError):
            break
    if c_to_b:
        await be_writer.drain()
    # Geef andere coroutines een kans na de synchrone handshake + drain.
    await asyncio.sleep(0)

    client_task: asyncio.Task = asyncio.ensure_future(client_reader.read(16384))
    be_task:     asyncio.Task = asyncio.ensure_future(be_reader.read(16384))

    # IDLE_TIMEOUT: sluit keep-alive verbindingen die te lang niets doen.
    IDLE_TIMEOUT = 30.0

    try:
        while True:
            done, _ = await asyncio.wait(
                [client_task, be_task],
                return_when=asyncio.FIRST_COMPLETED,
                timeout=IDLE_TIMEOUT,
            )
            if not done:
                # Timeout — geen activiteit, sluit de verbinding.
                break

            if client_task in done:
                encrypted = client_task.result()
                if not encrypted:
                    break
                incoming.write(encrypted)
                while True:
                    try:
                        plain = ssl_obj.read(16384)
                        if not plain:
                            break
                        be_writer.write(_maybe_rewrite(plain))
                        c_to_b += len(plain)
                    except (ssl.SSLWantReadError, ssl.SSLZeroReturnError):
                        break
                await be_writer.drain()
                await flush_to_client()
                client_task = asyncio.ensure_future(client_reader.read(16384))

            if be_task in done:
                plain = be_task.result()
                if not plain:
                    try:
                        ssl_obj.unwrap()
                        await flush_to_client()
                    except Exception:
                        pass
                    break
                try:
                    ssl_obj.write(plain)
                    b_to_c += len(plain)
                    await flush_to_client()
                except ssl.SSLError:
                    break
                be_task = asyncio.ensure_future(be_reader.read(16384))
    finally:
        for t in (client_task, be_task):
            if not t.done():
                t.cancel()

    return c_to_b, b_to_c


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
    now = time.time()
    if exp is None or now > exp:
        if token in _sessions:
            del _sessions[token]
        return False
    _sessions[token] = now + SESSION_TTL  # sliding expiry
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
    code = f"{secrets.randbelow(100_000_000):08d}"
    _otp_store[code] = (time.time() + OTP_TTL, False)
    return code


def _validate_tg_init_data(init_data: str, bot_token: str) -> bool:
    """Valideer Telegram WebApp initData via HMAC-SHA256."""
    try:
        params = dict(urllib.parse.parse_qsl(init_data, keep_blank_values=True))
        received_hash = params.pop("hash", None)
        if not received_hash:
            return False
        if time.time() - int(params.get("auth_date", 0)) > 86400:
            return False  # ouder dan 24 uur
        data_check = "\n".join(f"{k}={v}" for k, v in sorted(params.items()))
        secret = hmac.new(b"WebAppData", bot_token.encode(), hashlib.sha256).digest()
        computed = hmac.new(secret, data_check.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(computed, received_hash)
    except Exception:
        return False


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


# ── TOTP (RFC 6238) ───────────────────────────────────────────────────────────

_totp_used_steps: dict[int, float] = {}   # replay-bescherming: step → first-use timestamp


def _totp_code(secret_b32: str, step: int) -> str:
    """Bereken TOTP-code voor een gegeven time-step (HMAC-SHA1, 6 cijfers)."""
    key = base64.b32decode(secret_b32.upper().replace(" ", "").replace("-", ""))
    msg = step.to_bytes(8, "big")
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFF_FFFF
    return f"{code % 1_000_000:06d}"


_TOTP_GRACE = 5.0   # seconden: sta tweede identieke POST toe (browser double-submit)


def _totp_verify(code: str, secret_b32: str, window: int = 1) -> bool:
    """Verifieer een TOTP-code; sta ±window tijdstappen toe voor klokafwijking.
    Markeert de gebruikte stap om replay-aanvallen te voorkomen.
    Binnen _TOTP_GRACE seconden na first-use wordt dezelfde stap nogmaals geaccepteerd
    (browsers sturen de POST soms twee keer op aparte TCP-verbindingen).
    Alle kandidaat-codes worden altijd berekend en vergeleken (constant-time)."""
    now = time.time()
    step = int(now // 30)
    steps = [step + delta for delta in range(-window, window + 1)]
    # Bereken alle codes en vergelijk alle — geen early-exit om timing-lekkage te voorkomen
    matched_step = None
    for s in steps:
        if hmac.compare_digest(_totp_code(secret_b32, s), code):
            matched_step = s  # overschrijf bij elke match; slaat laatste op
    if matched_step is None:
        return False
    # Atomaire insert: setdefault geeft bestaande waarde terug als stap al bekend is
    first_use = _totp_used_steps.setdefault(matched_step, now)
    if first_use == now:
        # Eerste gebruik — opruimen van oude stappen
        cutoff = step - window - 10
        for old in [k for k in _totp_used_steps if k < cutoff]:
            del _totp_used_steps[old]
        if len(_totp_used_steps) > 500:
            _totp_used_steps.clear()
        return True
    if now - first_use <= _TOTP_GRACE:
        # Tweede verzoek binnen genade-periode — browser double-submit
        return True
    # Stap al gebruikt buiten genade-periode: replay-aanval
    return False


def _totp_new_secret() -> str:
    """Genereer een nieuw willekeurig base32 TOTP-geheim (20 bytes = 160 bits)."""
    return base64.b32encode(secrets.token_bytes(20)).decode()


def _totp_uri(secret: str, issuer: str = "SNI Proxy", account: str = "admin") -> str:
    """Genereer otpauth:// URI voor QR-code of handmatige invoer in authenticator-app."""
    issuer_enc  = urllib.parse.quote(issuer)
    account_enc = urllib.parse.quote(account)
    return (f"otpauth://totp/{issuer_enc}:{account_enc}"
            f"?secret={secret}&issuer={issuer_enc}&algorithm=SHA1&digits=6&period=30")


def _totp_qr_svg(uri: str) -> Optional[str]:
    """Genereer QR-code als SVG data-URI. Geeft None als segno niet beschikbaar is."""
    if not _SEGNO_OK:
        return None
    buf = io.BytesIO()
    segno.make(uri, error="M").save(buf, kind="svg", svgclass=None, lineclass=None,
                                    omitsize=True, xmldecl=False, nl=False)
    svg = buf.getvalue()
    encoded = base64.b64encode(svg).decode()
    return f"data:image/svg+xml;base64,{encoded}"


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
    _is_active = False

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
            _stats["tls_unknown"] += 1
            return

        backend = cfg.tls_routes.get(sni.lower())
        if not backend:
            _stats["tls_unknown"] += 1
            logger.warning(f"[{src}] SNI={sni} — no route configured, dropped")
            return

        if not backend.enabled:
            sni_key = sni.lower()
            _stats["tls_rej"][sni_key] = _stats["tls_rej"].get(sni_key, 0) + 1
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
            asyncio.create_task(_tg_alert_backend(
                backend.name, f"connect timeout ({cfg.connect_timeout}s)", cfg))
            return
        except OSError as exc:
            logger.error(f"[{src}] cannot connect → {backend.name} ({backend.host}:{backend.port}): {exc}")
            asyncio.create_task(_tg_alert_backend(backend.name, str(exc), cfg))
            return

        sni_key = sni.lower()
        _stats["tls_ok"][sni_key] = _stats["tls_ok"].get(sni_key, 0) + 1
        _stats["active_tls"] += 1
        _is_active = True

        if backend.notify and cfg.telegram.bot_token:
            asyncio.create_task(_tg_notify_connect(sni, backend, src, cfg))

        if backend.tls_terminate:
            ssl_ctx = server._ssl_ctx_for(backend)
            if not ssl_ctx:
                logger.error(f"[{src}] tls_terminate=True maar geen cert beschikbaar voor {sni}")
                return
            be_host_hdr = backend.host if backend.port == 80 else f"{backend.host}:{backend.port}"
            up, down = await _tls_terminate_and_pipe(
                initial, client_reader, client_writer, ssl_ctx, be_reader, be_writer,
                backend_host=be_host_hdr,
            )
        else:
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
        logger.error(f"[{src}] unhandled error: {exc.__class__.__name__}: {exc}")
    finally:
        if _is_active:
            _stats["active_tls"] -= 1
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

def _make_login_html(totp_enabled: bool) -> str:
    """Genereer de inlogpagina: TOTP-modus als totp_enabled, anders legacy OTP."""
    totp_block = """
  <!-- TOTP modus: direct code invoeren vanuit authenticator-app -->
  <div id="stepTotp" class="step active">
    <p style="color:#555;font-size:.88rem;margin-bottom:1.25rem">
      Voer de 6-cijferige code in uit je authenticator-app.
    </p>
    <input id="totpInput" type="text" inputmode="numeric" maxlength="6" placeholder="000000"
           oninput="this.value=this.value.replace(/[^0-9]/g,'')"
           onkeydown="if(event.key==='Enter')verifyTotp()">
    <button id="btnTotp" onclick="verifyTotp()">Inloggen</button>
    <div id="msgTotp" class="msg"></div>
  </div>
""" if totp_enabled else """
  <!-- Legacy OTP modus: stap 1 = code aanvragen -->
  <div id="step1" class="step active">
    <button id="btnSend" onclick="requestCode()">Stuur inlogcode</button>
    <p class="hint">Er wordt een eenmalige code verstuurd via e-mail en/of Telegram.</p>
    <div id="msg1" class="msg"></div>
  </div>

  <!-- Legacy OTP modus: stap 2 = code invoeren -->
  <div id="step2" class="step">
    <p style="color:#555;font-size:.88rem;margin-bottom:1.25rem">
      Er is een 8-cijferige code verstuurd.<br>De code is 5 minuten geldig.
    </p>
    <input id="codeInput" type="text" maxlength="8" placeholder="00000000"
           oninput="this.value=this.value.replace(/[^0-9]/g,'')"
           onkeydown="if(event.key==='Enter')verifyCode()">
    <button id="btnVerify" onclick="verifyCode()">Inloggen</button>
    <p class="hint" style="cursor:pointer" onclick="backToStep1()">&larr; Nieuwe code aanvragen</p>
    <div id="msg2" class="msg"></div>
  </div>
"""

    totp_script = """
let _totpBusy = false;
async function verifyTotp() {
  if (_totpBusy) return;
  _totpBusy = true;
  const code = document.getElementById('totpInput').value.trim();
  const btn = document.getElementById('btnTotp');
  btn.disabled = true; btn.textContent = 'Controleren\u2026';
  if (code.length !== 6) {
    setMsg('msgTotp', 'Voer een 6-cijferige code in.', false);
    btn.disabled = false; btn.textContent = 'Inloggen';
    _totpBusy = false; return;
  }
  try {
    const r = await fetch('/api/auth/verify-totp', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({code}),
    });
    const d = await r.json();
    if (r.ok) { window.location.replace('/'); return; }
    setMsg('msgTotp', d.error || 'Ongeldige code.', false);
  } catch (e) {
    // Verbinding verbroken — de server heeft de login mogelijk al verwerkt.
    // Navigeer naar / : als de cookie gezet was → dashboard, anders → terug naar /login.
    window.location.replace('/');
    return;
  }
  _totpBusy = false;
  btn.disabled = false; btn.textContent = 'Inloggen';
}
""" if totp_enabled else """
function show(id) {
  ['step1','step2'].forEach(s => document.getElementById(s).classList.remove('active'));
  document.getElementById(id).classList.add('active');
}
async function requestCode() {
  const btn = document.getElementById('btnSend');
  btn.disabled = true; btn.textContent = 'Versturen\u2026';
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
    btn.disabled = false; btn.textContent = 'Stuur inlogcode';
  }
}
async function verifyCode() {
  const code = document.getElementById('codeInput').value.trim();
  if (code.length !== 8) { setMsg('msg2', 'Voer een 8-cijferige code in.', false); return; }
  const btn = document.getElementById('btnVerify');
  btn.disabled = true; btn.textContent = 'Controleren\u2026';
  try {
    const r = await fetch('/api/auth/verify', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({code}),
    });
    const d = await r.json();
    if (!r.ok) { setMsg('msg2', d.error || 'Ongeldige code.', false); return; }
    window.location.href = '/';
  } catch (e) {
    setMsg('msg2', 'Netwerkfout: ' + e, false);
  } finally {
    btn.disabled = false; btn.textContent = 'Inloggen';
  }
}
function backToStep1() {
  document.getElementById('codeInput').value = '';
  setMsg('msg2', '', false);
  show('step1');
}
"""

    return ("""\
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
                     border-radius: 8px; font-size: 1.4rem; text-align: center;
                     letter-spacing: .3em; margin-bottom: 1rem; }
  input[type=text]:focus { outline: 2px solid #6366f1; border-color: transparent; }
  .msg { margin-top: 1rem; padding: .6rem .9rem; border-radius: 8px;
         font-size: .85rem; display: none; }
  .msg-ok  { background: #dcf5e7; color: #166534; display: block; }
  .msg-err { background: #fde8e8; color: #991b1b; display: block; }
  .hint { color: #9ca3af; font-size: .8rem; margin-top: 1.5rem; }
  @media (max-width: 400px) { .card { padding: 2rem 1.25rem; width: 100%; } }
</style>
</head>
<body>
<div class="card">
  <div style="display:flex;align-items:center;justify-content:center;gap:.6rem;margin-bottom:.4rem">
    """ + _LOGO_36 + """
    <h1>SNI Proxy</h1>
  </div>
  <p class="sub">Admin toegang vereist</p>
""" + totp_block + """
</div>
<script>
function setMsg(id, text, ok) {
  const el = document.getElementById(id);
  el.textContent = text;
  el.className = 'msg ' + (ok ? 'msg-ok' : 'msg-err');
}
""" + totp_script + """
</script>
</body>
</html>
""")


TOTP_SETUP_HTML = """\
<!DOCTYPE html>
<html lang="nl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SNI Proxy — TOTP instellen</title>
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, sans-serif; background: #f0f2f5;
         display: flex; align-items: center; justify-content: center;
         min-height: 100vh; color: #222; padding: 1rem; }
  .card { background: #fff; border-radius: 12px; padding: 2rem 2.5rem;
          box-shadow: 0 2px 12px rgba(0,0,0,.12); width: 460px; max-width: 100%; }
  h1 { font-size: 1.2rem; font-weight: 600; margin-bottom: .3rem; }
  .sub { color: #888; font-size: .85rem; margin-bottom: 1.5rem; }
  h2 { font-size: .9rem; font-weight: 600; color: #444; margin: 1.2rem 0 .5rem; }
  .secret-box { background: #f7f7f7; border: 1px solid #e5e7eb; border-radius: 8px;
                padding: .75rem 1rem; font-family: monospace; font-size: 1rem;
                letter-spacing: .1em; word-break: break-all; color: #111;
                display: flex; align-items: center; justify-content: space-between; gap: .5rem; }
  .secret-text { flex: 1; }
  .btn-copy { background: #6366f1; color: #fff; border: none; border-radius: 6px;
              padding: .3rem .7rem; font-size: .8rem; cursor: pointer; white-space: nowrap; }
  .btn-copy:hover { background: #4f46e5; }
  .uri-box { background: #f7f7f7; border: 1px solid #e5e7eb; border-radius: 8px;
             padding: .6rem .9rem; font-size: .75rem; font-family: monospace;
             word-break: break-all; color: #555; margin-bottom: .4rem; }
  ol { padding-left: 1.2rem; color: #555; font-size: .85rem; line-height: 1.7; margin-bottom: 1rem; }
  input[type=text] { width: 100%; padding: .6rem .8rem; border: 1px solid #d1d5db;
                     border-radius: 8px; font-size: 1.4rem; text-align: center;
                     letter-spacing: .3em; margin-bottom: .75rem; }
  input[type=text]:focus { outline: 2px solid #6366f1; border-color: transparent; }
  .btn-primary { width: 100%; padding: .65rem; border: none; border-radius: 8px;
                 background: #6366f1; color: #fff; font-size: .95rem; cursor: pointer;
                 font-weight: 500; transition: background .15s; }
  .btn-primary:hover { background: #4f46e5; }
  .btn-primary:disabled { background: #a5b4fc; cursor: wait; }
  .btn-back { display: block; margin-top: .75rem; text-align: center; color: #6366f1;
              font-size: .85rem; text-decoration: none; cursor: pointer; background: none;
              border: none; width: 100%; }
  .msg { margin-top: .75rem; padding: .6rem .9rem; border-radius: 8px; font-size: .85rem; display: none; }
  .msg-ok  { background: #dcf5e7; color: #166534; display: block; }
  .msg-err { background: #fde8e8; color: #991b1b; display: block; }
  .warn { background: #fff7ed; border: 1px solid #fed7aa; border-radius: 8px;
          padding: .6rem .9rem; font-size: .83rem; color: #9a3412; margin-bottom: 1rem; }
  .qr-wrap { display: flex; justify-content: center; margin: .75rem 0 .5rem; }
  .qr-wrap canvas, .qr-wrap img { border-radius: 8px; border: 1px solid #e5e7eb; display: block; }
</style>
</head>
<body>
<div class="card">
  <h1>🔐 TOTP Authenticatie instellen</h1>
  <p class="sub">Vervang e-mail/Telegram OTP door een authenticator-app</p>

  <div id="setupSection">
    <div class="warn">
      ⚠️ Sla het geheim veilig op als back-up. Als je de app kwijtraakt
      zonder back-up, ben je buitengesloten.
    </div>

    <h2>Stap 1 — Scan de QR-code</h2>
    <ol>
      <li>Open Google Authenticator, Authy of Bitwarden</li>
      <li>Kies "Account toevoegen" → "QR-code scannen"</li>
      <li>Scan de code hieronder — of voer het geheim handmatig in</li>
    </ol>
    <div class="qr-wrap" id="qrWrap" style="display:none">
      <img id="qrImg" alt="QR-code" width="200" height="200">
    </div>

    <div class="secret-box">
      <span class="secret-text" id="secretText">Laden…</span>
      <button class="btn-copy" onclick="copySecret()">Kopieer</button>
    </div>

    <h2>Stap 2 — Of gebruik de otpauth:// link</h2>
    <p style="font-size:.82rem;color:#888;margin-bottom:.4rem">
      Op mobiel kun je de link direct aantikken om de app te openen.
    </p>
    <div class="uri-box" id="uriBox">Laden…</div>
    <button class="btn-copy" style="margin-bottom:1rem" onclick="copyUri()">Kopieer link</button>

    <h2>Stap 3 — Verificatie</h2>
    <p style="font-size:.85rem;color:#555;margin-bottom:.75rem">
      Voer een code uit de app in om te bevestigen dat het klopt.
    </p>
    <input id="verifyInput" type="text" inputmode="numeric" maxlength="6" placeholder="000000"
           oninput="this.value=this.value.replace(/[^0-9]/g,'')"
           onkeydown="if(event.key==='Enter')enableTotp()">
    <button class="btn-primary" id="btnEnable" onclick="enableTotp()">TOTP activeren</button>
    <div id="msgSetup" class="msg"></div>
  </div>

  <button class="btn-back" onclick="window.location.href='/'">← Terug naar dashboard</button>
</div>

<script>
let _secret = '', _uri = '';

async function load() {
  try {
    const r = await fetch('/api/totp/new-secret');
    const d = await r.json();
    if (!r.ok) { document.getElementById('secretText').textContent = 'Fout: ' + d.error; return; }
    _secret = d.secret;
    _uri    = d.uri;
    // Toon geheim in groepen van 4
    document.getElementById('secretText').textContent =
      _secret.match(/.{1,4}/g).join(' ');
    document.getElementById('uriBox').textContent = _uri;
    if (d.qr_svg) {
      document.getElementById('qrImg').src = d.qr_svg;
      document.getElementById('qrWrap').style.display = 'flex';
    }
  } catch(e) {
    document.getElementById('secretText').textContent = 'Fout: ' + e;
  }
}

function copySecret() {
  navigator.clipboard.writeText(_secret).then(() => {
    const btn = event.target; btn.textContent = 'Gekopieerd!';
    setTimeout(() => btn.textContent = 'Kopieer', 1500);
  });
}

function copyUri() {
  navigator.clipboard.writeText(_uri).then(() => {
    const btn = event.target; btn.textContent = 'Gekopieerd!';
    setTimeout(() => btn.textContent = 'Kopieer link', 1500);
  });
}

function setMsg(text, ok) {
  const el = document.getElementById('msgSetup');
  el.textContent = text;
  el.className = 'msg ' + (ok ? 'msg-ok' : 'msg-err');
}

async function enableTotp() {
  const code = document.getElementById('verifyInput').value.trim();
  if (code.length !== 6) { setMsg('Voer een 6-cijferige code in.', false); return; }
  const btn = document.getElementById('btnEnable');
  btn.disabled = true; btn.textContent = 'Activeren\u2026';
  try {
    const r = await fetch('/api/totp/enable', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({secret: _secret, code}),
    });
    const d = await r.json();
    if (!r.ok) { setMsg(d.error || 'Verificatie mislukt.', false); return; }
    setMsg('TOTP geactiveerd! Je wordt doorgestuurd naar het dashboard.', true);
    setTimeout(() => window.location.href = '/', 1800);
  } catch(e) {
    setMsg('Netwerkfout: ' + e, false);
  } finally {
    btn.disabled = false; btn.textContent = 'TOTP activeren';
  }
}

load();
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
  .topbar { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between;
            max-width: 800px; margin-bottom: 1.5rem; gap: .6rem; }
  .topbar-btns { display: flex; gap: .5rem; flex-wrap: wrap; }
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
  .host a { color: inherit; text-decoration: none; }
  .host a:hover { color: #6366f1; text-decoration: underline; }
  .backend { color: #777; font-size: .82rem; font-family: monospace; }
  .route-stats { font-size: .76rem; margin-top: .15rem; color: #aaa; }
  .s-ok  { color: #16a34a; }
  .s-rej { color: #dc2626; }
  .auth-card { display: flex; align-items: center; gap: .75rem; flex-wrap: wrap; }
  .auth-label { font-size: .85rem; font-weight: 600; color: #444; white-space: nowrap; }
  .auth-status { font-size: .85rem; color: #9ca3af; display: flex; align-items: center; gap: .4rem; flex-wrap: wrap; }
  .btn-auth { border: 1px solid #d1d5db; background: #f9fafb; border-radius: 6px;
              padding: .25rem .7rem; font-size: .8rem; cursor: pointer; }
  .btn-auth-danger { border-color: #fca5a5; background: #fef2f2; color: #b91c1c; }
  .btn-auth-primary { border: none; background: #6366f1; color: #fff; padding: .3rem .8rem; }
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
  .kpi-row { display: flex; gap: .75rem; max-width: 800px; margin-bottom: 1.5rem; flex-wrap: wrap; }
  .kpi { background: #fff; border-radius: 10px; box-shadow: 0 1px 6px rgba(0,0,0,.1);
         padding: .75rem 1.25rem; flex: 1; min-width: 110px; }
  .kpi-label { font-size: .72rem; color: #888; text-transform: uppercase; letter-spacing: .05em; margin-bottom: .3rem; }
  .kpi-value { font-size: 1.6rem; font-weight: 700; color: #111; line-height: 1; }
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
    td:nth-child(4) { display: none; }
    td:nth-child(5), td:nth-child(6) { display: inline-block; vertical-align: middle;
                                        margin-right: .5rem; margin-top: .5rem; }
    .add-card { padding: 1rem; }
    .fields { grid-template-columns: 1fr; }
    .btn-add { width: 100%; }
    .kpi-row { display: grid; grid-template-columns: 1fr 1fr; gap: .5rem; }
    .kpi { min-width: unset; padding: .6rem 1rem; }
  }
</style>
</head>
<body>
<div class="topbar">
  <div style="display:flex;align-items:center;gap:.6rem">
    """ + _LOGO_32 + """
    <h1>SNI Proxy</h1>
  </div>
  <div class="topbar-btns">
    <button class="btn-logout" onclick="resetStats()" title="Verbindingstellers resetten">&#x21BA; Tellers</button>
    <button class="btn-logout" onclick="logout()">Uitloggen</button>
  </div>
</div>
<div class="kpi-row">
  <div class="kpi"><div class="kpi-label">Actief TLS</div><div class="kpi-value" id="k-tls">—</div></div>
  <div class="kpi"><div class="kpi-label">Actief TCP</div><div class="kpi-value" id="k-tcp">—</div></div>
  <div class="kpi"><div class="kpi-label">Verbindingen</div><div class="kpi-value" id="k-total">—</div></div>
  <div class="kpi"><div class="kpi-label">Onbekende SNI</div><div class="kpi-value" id="k-unknown">—</div></div>
  <div class="kpi"><div class="kpi-label">Uptime</div><div class="kpi-value" id="k-uptime">—</div></div>
</div>

<table>
  <thead>
    <tr>
      <th>Hostname</th>
      <th>Naam</th>
      <th>Status</th>
      <th>Auto-uit</th>
      <th>Aan / Uit</th>
      <th></th>
    </tr>
  </thead>
  <tbody id="tbody">
    <tr><td colspan="6" style="color:#aaa;padding:1.5rem">Laden&hellip;</td></tr>
  </tbody>
</table>

<h2 style="max-width:800px;margin-top:2rem;margin-bottom:.75rem;font-size:1rem;font-weight:600;color:#555">TCP routes</h2>
<table>
  <thead>
    <tr>
      <th>Luisterpoort</th>
      <th>Naam</th>
      <th>Status</th>
      <th>Auto-uit</th>
      <th>Aan / Uit</th>
    </tr>
  </thead>
  <tbody id="tcp-tbody">
    <tr><td colspan="5" style="color:#aaa;padding:1.5rem">Laden&hellip;</td></tr>
  </tbody>
</table>

<div class="add-card">
  <div class="auth-card">
    <span class="auth-label">🔐 Authenticatie:</span>
    <span id="totpStatus" class="auth-status">Laden&hellip;</span>
  </div>
</div>

<div class="add-card">
  <h2>Route toevoegen</h2>
  <div class="fields">
    <input id="f-hostname" placeholder="hostname (bijv. app.budie.eu)" autocomplete="off">
    <input id="f-host"     placeholder="backend host (bijv. 192.168.2.10)" autocomplete="off">
    <input id="f-port"     placeholder="poort" type="number" min="1" max="65535" autocomplete="off">
    <input id="f-name"     placeholder="label" autocomplete="off">
  </div>
  <label style="display:flex;align-items:center;gap:.5rem;font-size:.88rem;color:#555;margin:.75rem 0">
    <input type="checkbox" id="f-tls-terminate">
    HTTP backend (TLS termineren — proxy ontsleutelt TLS, stuurt plain HTTP door)
  </label>
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
        <td class="host">${rt.enabled ? `<a href="https://${esc(rt.hostname)}" target="_blank" rel="noopener noreferrer">${esc(rt.hostname)}</a>` : esc(rt.hostname)}</td>
        <td class="backend">
          ${esc(rt.name)}${rt.tls_terminate ? ' <span style="font-size:.75rem;background:#e0f2fe;color:#0369a1;border-radius:4px;padding:1px 5px;vertical-align:middle">HTTP</span>' : ''}
          <div class="route-stats">
            <span class="s-ok">${rt.ok} verbindingen</span>${rt.rejected ? ` &middot; <span class="s-rej">${rt.rejected} geweigerd</span>` : ''}
          </div>
          <div style="font-size:.75rem;color:#e06000;min-height:.9rem" id="cd-tls-${esc(rt.hostname)}"></div>
        </td>
        <td><span class="badge ${rt.enabled ? 'badge-on' : 'badge-off'}">${rt.enabled ? 'Aan' : 'Uit'}</span></td>
        <td style="white-space:nowrap">
          <input type="number" min="0" style="width:4rem;padding:2px 4px;border:1px solid #ccc;border-radius:4px;font-size:.85rem"
                 value="${rt.auto_disable_minutes}"
                 title="Minuten tot auto-uitschakelen (0 = nooit)"
                 onchange='setAutoDisable(${JSON.stringify(rt.hostname)}, this.value, "tls")'>
          <span style="font-size:.8rem;color:#888">min</span>
        </td>
        <td>
          <label class="toggle" title="${rt.enabled ? 'Klik om uit te zetten' : 'Klik om aan te zetten'}">
            <input type="checkbox" ${rt.enabled ? 'checked' : ''}
                   onchange='toggle(${JSON.stringify(rt.hostname)}, this)'>
            <span class="slider"></span>
          </label>
        </td>
        <td><button class="btn-del" onclick='remove(${JSON.stringify(rt.hostname)})'>Verwijder</button></td>
      </tr>
    `).join('') : '<tr><td colspan="6" style="color:#aaa;padding:1.5rem">Geen routes geconfigureerd.</td></tr>';
    routes.forEach(rt => {
      if (rt.enabled_until) _startCountdown('cd-tls-' + rt.hostname, rt.enabled_until);
    });
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
    await loadTcp();
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
  const hostname     = document.getElementById('f-hostname').value.trim().toLowerCase();
  const host         = document.getElementById('f-host').value.trim();
  const port         = parseInt(document.getElementById('f-port').value, 10);
  const name         = document.getElementById('f-name').value.trim();
  const tls_terminate = document.getElementById('f-tls-terminate').checked;
  if (!hostname || !host || !port || !name) { showMsg('Vul alle velden in.', false); return; }
  try {
    const r = await fetch('/api/routes', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({hostname, host, port, name, tls_terminate}),
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
    document.getElementById('f-tls-terminate').checked = false;
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
        <td class="backend">
          ${esc(rt.name)}
          <div class="route-stats">
            <span class="s-ok">${rt.ok} verbindingen</span>${rt.rejected ? ` &middot; <span class="s-rej">${rt.rejected} geweigerd</span>` : ''}
          </div>
          <div style="font-size:.75rem;color:#e06000;min-height:.9rem" id="cd-tcp-${rt.listen_port}"></div>
        </td>
        <td><span class="badge ${rt.enabled ? 'badge-on' : 'badge-off'}">${rt.enabled ? 'Aan' : 'Uit'}</span></td>
        <td style="white-space:nowrap">
          <input type="number" min="0" style="width:4rem;padding:2px 4px;border:1px solid #ccc;border-radius:4px;font-size:.85rem"
                 value="${rt.auto_disable_minutes}"
                 title="Minuten tot auto-uitschakelen (0 = nooit)"
                 onchange='setAutoDisable(${rt.listen_port}, this.value, "tcp")'>
          <span style="font-size:.8rem;color:#888">min</span>
        </td>
        <td>
          <label class="toggle" title="${rt.enabled ? 'Klik om uit te zetten' : 'Klik om aan te zetten'}">
            <input type="checkbox" ${rt.enabled ? 'checked' : ''}
                   onchange='toggleTcp(${rt.listen_port}, this)'>
            <span class="slider"></span>
          </label>
        </td>
      </tr>
    `).join('') : '<tr><td colspan="5" style="color:#aaa;padding:1.5rem">Geen TCP routes geconfigureerd.</td></tr>';
    routes.forEach(rt => {
      if (rt.enabled_until) _startCountdown('cd-tcp-' + rt.listen_port, rt.enabled_until);
    });
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
    await load();
    await loadTcp();
  } catch (e) {
    el.checked = !el.checked;
    showMsg('Netwerkfout: ' + e, false);
  } finally { el.disabled = false; }
}

async function setAutoDisable(id, val, type) {
  const minutes = parseInt(val, 10);
  if (isNaN(minutes) || minutes < 0) return;
  const url = type === 'tls'
    ? '/api/routes/' + encodeURIComponent(id) + '/auto-disable'
    : '/api/tcp-routes/' + id + '/auto-disable';
  try {
    const r = await fetch(url, {method: 'POST', headers: {'Content-Type': 'application/json'},
                                body: JSON.stringify({minutes})});
    if (!r.ok) { showMsg('Fout bij instellen auto-disable.', false); return; }
    showMsg(`Auto-uitschakelen ingesteld op ${minutes} min.`, true);
    if (type === 'tls') await load(); else await loadTcp();
  } catch (e) { showMsg('Netwerkfout: ' + e, false); }
}

const _cdTimers = {};
function _startCountdown(elId, until) {
  if (_cdTimers[elId]) clearInterval(_cdTimers[elId]);
  _cdTimers[elId] = setInterval(() => {
    const el = document.getElementById(elId);
    if (!el) { clearInterval(_cdTimers[elId]); return; }
    const rem = Math.max(0, Math.round(until - Date.now() / 1000));
    const m = Math.floor(rem / 60), s = rem % 60;
    el.textContent = `Uit over ${m}:${String(s).padStart(2,'0')}`;
    if (rem === 0) clearInterval(_cdTimers[elId]);
  }, 1000);
}

async function logout() {
  await fetch('/api/auth/logout', {method: 'POST'});
  window.location.href = '/login';
}

async function resetStats() {
  if (!confirm('Verbindingstellers resetten?')) return;
  const r = await fetch('/api/stats/clear', {method: 'POST'});
  if (r.ok) { showMsg('Tellers gereset.', true); await load(); await loadTcp(); await loadStats(); }
  else showMsg('Resetten mislukt.', false);
}

async function disableTotp() {
  if (!confirm('TOTP uitschakelen? Inloggen gaat dan weer via e-mail/Telegram.')) return;
  const r = await fetch('/api/totp/disable', {method: 'POST'});
  const d = await r.json();
  if (r.ok) { showMsg('TOTP uitgeschakeld.', true); loadTotpStatus(); }
  else showMsg(d.error || 'Fout.', false);
}

async function loadTotpStatus() {
  try {
    const r = await fetch('/api/totp/status');
    const d = await r.json();
    const el = document.getElementById('totpStatus');
    if (!el) return;
    if (d.enabled) {
      el.innerHTML = `<span style="color:#166534;font-weight:600">&#10003; Actief</span>`
        + `<button class="btn-auth" onclick="if(confirm('TOTP-sleutel vervangen? Je moet daarna je authenticator-app opnieuw instellen.'))window.location.href='/totp-setup'">Vervangen</button>`
        + `<button class="btn-auth btn-auth-danger" onclick="disableTotp()">Uitschakelen</button>`;
    } else {
      el.innerHTML = `<span style="color:#9ca3af">Niet actief (e-mail/Telegram OTP)</span>`
        + `<button class="btn-auth btn-auth-primary" onclick="window.location.href='/totp-setup'">Instellen</button>`;
    }
  } catch(e) {}
}

loadTotpStatus();

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

function fmtUptime(secs) {
  if (secs < 60) return secs + 's';
  const m = Math.floor(secs / 60) % 60, h = Math.floor(secs / 3600) % 24, d = Math.floor(secs / 86400);
  if (d) return d + 'd ' + h + 'u';
  if (h) return h + 'u ' + m + 'm';
  return m + 'm';
}

async function loadStats() {
  try {
    const r = await fetch('/api/overview');
    if (!r.ok) return;
    const d = await r.json();
    document.getElementById('k-tls').textContent = d.active_tls;
    document.getElementById('k-tcp').textContent = d.active_tcp;
    const total = d.tls_routes.reduce((s, r) => s + (r.ok || 0), 0)
                + d.tcp_routes.reduce((s, r) => s + (r.ok || 0), 0);
    document.getElementById('k-total').textContent = total;
    document.getElementById('k-unknown').textContent = d.unknown_sni || 0;
    document.getElementById('k-uptime').textContent = fmtUptime(d.uptime_secs);
  } catch (e) {}
}

load();
loadTcp();
loadStats();
setInterval(loadStats, 15000);
setInterval(() => { load(); loadTcp(); }, 15000);

</script>
</body>
</html>
"""


MINI_APP_HTML = """\
<!DOCTYPE html>
<html lang="nl">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=no">
  <title>Proxy Beheer</title>
  <script src="https://telegram.org/js/telegram-web-app.js"></script>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: var(--tg-theme-bg-color, #fff);
      color: var(--tg-theme-text-color, #000);
      padding-bottom: 76px;
    }
    .topbar {
      position: sticky; top: 0; z-index: 10;
      background: var(--tg-theme-secondary-bg-color, #f4f4f4);
      padding: 12px 16px;
      display: flex; align-items: center; justify-content: space-between;
      border-bottom: 1px solid rgba(128,128,128,.15);
    }
    .topbar-title { font-size: 17px; font-weight: 700; }
    .topbar-meta { font-size: 12px; color: var(--tg-theme-hint-color, #8e8e93); text-align: right; }
    .topbar-meta div + div { margin-top: 2px; }
    .section { margin-top: 20px; }
    .section-header {
      font-size: 13px; font-weight: 600; letter-spacing: .4px; text-transform: uppercase;
      color: var(--tg-theme-hint-color, #8e8e93);
      padding: 0 16px 8px;
    }
    .card-list { background: var(--tg-theme-secondary-bg-color, #f4f4f4); }
    .route-row {
      display: flex; align-items: center; gap: 12px;
      padding: 12px 16px;
      border-bottom: 1px solid rgba(128,128,128,.1);
    }
    .route-row:last-child { border-bottom: none; }
    .route-icon {
      width: 36px; height: 36px; border-radius: 9px; flex-shrink: 0;
      background: var(--tg-theme-button-color, #2481cc);
      display: flex; align-items: center; justify-content: center; font-size: 19px;
    }
    .route-info { flex: 1; min-width: 0; }
    .route-name { font-size: 15px; font-weight: 500; }
    .route-host {
      font-size: 12px; color: var(--tg-theme-hint-color, #8e8e93);
      margin-top: 2px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
    }
    .route-stats { font-size: 11px; margin-top: 3px; }
    .route-timer { font-size: 11px; color: #e06000; margin-top: 2px; }
    .ok  { color: #34c759; }
    .rej { color: #ff3b30; }
    .toggle { position: relative; width: 51px; height: 31px; flex-shrink: 0; }
    .toggle input {
      opacity: 0; position: absolute; inset: 0; width: 100%; height: 100%;
      margin: 0; cursor: pointer; z-index: 1;
    }
    .t-track {
      position: absolute; inset: 0; border-radius: 31px;
      background: #e5e5ea; transition: background .2s;
    }
    .t-thumb {
      position: absolute; top: 2px; left: 2px;
      width: 27px; height: 27px; border-radius: 50%;
      background: white; box-shadow: 0 2px 4px rgba(0,0,0,.3);
      transition: transform .2s;
    }
    .toggle input:checked ~ .t-track { background: #34c759; }
    .toggle input:checked ~ .t-thumb { transform: translateX(20px); }
    .toggle input:disabled { cursor: not-allowed; }
    .toggle input:disabled ~ .t-track { opacity: .5; }
    .bottom-bar {
      position: fixed; bottom: 0; left: 0; right: 0;
      padding: 10px 16px;
      background: var(--tg-theme-bg-color, #fff);
      border-top: 1px solid rgba(128,128,128,.15);
    }
    .btn {
      width: 100%; padding: 14px;
      background: var(--tg-theme-button-color, #2481cc);
      color: var(--tg-theme-button-text-color, #fff);
      border: none; border-radius: 12px;
      font-size: 16px; font-weight: 600; cursor: pointer;
      transition: opacity .15s;
    }
    .btn:active { opacity: .7; }
    .btn:disabled { opacity: .5; cursor: not-allowed; }
    .toast {
      position: fixed; bottom: 76px; left: 50%;
      transform: translateX(-50%) translateY(8px);
      background: rgba(0,0,0,.75); color: white;
      padding: 8px 18px; border-radius: 20px;
      font-size: 14px; opacity: 0; pointer-events: none;
      transition: opacity .2s, transform .2s; white-space: nowrap;
    }
    .toast.on { opacity: 1; transform: translateX(-50%) translateY(0); }
    .msg { padding: 40px 16px; text-align: center; color: var(--tg-theme-hint-color, #8e8e93); }
    .err { color: #ff3b30; }
  </style>
</head>
<body>
<div class="topbar">
  <div class="topbar-title">&#x1F5A5;&#xFE0F; Proxy</div>
  <div class="topbar-meta">
    <div id="uptime">&#x2014;</div>
    <div id="active">&#x2014;</div>
  </div>
</div>
<div id="main"><div class="msg">Laden&#x2026;</div></div>
<div class="bottom-bar">
  <div style="display:flex;gap:10px">
    <button class="btn" id="btn-refresh" onclick="refresh()" style="flex:1;font-size:20px;padding:14px 0">&#x1F504;</button>
  </div>
</div>
<div class="toast" id="toast"></div>
<script>
const tg = window.Telegram.WebApp;
tg.expand(); tg.ready();

function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function fmtUp(s){const h=Math.floor(s/3600),m=Math.floor((s%3600)/60);return h?h+'u '+m+'m':m+'m';}
let _tt;
function toast(msg){const e=document.getElementById('toast');e.textContent=msg;e.classList.add('on');clearTimeout(_tt);_tt=setTimeout(()=>e.classList.remove('on'),2200);}

const _cdTimers={};
function _startCountdown(elId,until){
  if(_cdTimers[elId])clearInterval(_cdTimers[elId]);
  _cdTimers[elId]=setInterval(()=>{
    const el=document.getElementById(elId);
    if(!el){clearInterval(_cdTimers[elId]);delete _cdTimers[elId];return;}
    const rem=Math.max(0,Math.round(until-Date.now()/1000));
    const m=Math.floor(rem/60),s=rem%60;
    el.textContent='\u23F1 Uit over '+m+':'+String(s).padStart(2,'0');
    if(rem===0){clearInterval(_cdTimers[elId]);delete _cdTimers[elId];}
  },1000);
}

function icon(name){
  const n=name.toLowerCase();
  if(n.includes('ssh'))return'&#x1F510;';
  if(n.includes('padel')||n.includes('court')||n.includes('free'))return'&#x1F3BE;';
  if(n.includes('home')||n.includes('vm'))return'&#x1F3E0;';
  if(n.includes('proxy')||n.includes('admin'))return'&#x2699;&#xFE0F;';
  if(n.includes('cock')||n.includes('pf'))return'&#x1F527;';
  return'&#x1F310;';
}

function card(r,type){
  const id=type==='tls'?r.hostname:r.listen_port;
  const label=type==='tls'?esc(r.hostname):':'+r.listen_port;
  const ok=r.ok||0, rej=r.rejected||0;
  const stats='<span class="ok">'+ok+' verbindingen</span>'+(rej?' &middot; <span class="rej">'+rej+' geweigerd</span>':'');
  const cdId='cd-'+type+'-'+esc(String(id));
  return '<div class="route-row">'
    +'<div class="route-icon">'+icon(r.name)+'</div>'
    +'<div class="route-info">'
      +'<div class="route-name">'+esc(r.name)+'</div>'
      +'<div class="route-host">'+label+'</div>'
      +'<div class="route-stats">'+stats+'</div>'
      +'<div class="route-timer" id="'+cdId+'"></div>'
    +'</div>'
    +'<label class="toggle">'
      +'<input type="checkbox"'+(r.enabled?' checked':'')
        +' data-type="'+type+'" data-id="'+esc(String(id))+'" onchange="tog(this)">'
      +'<div class="t-track"></div><div class="t-thumb"></div>'
    +'</label>'
  +'</div>';
}

async function load(){
  const r=await fetch('/api/overview');
  if(r.status===401){document.getElementById('main').innerHTML='<div class="msg err">Niet ingelogd. Open via Telegram.</div>';return;}
  if(!r.ok){toast('Laden mislukt');return;}
  const d=await r.json();
  document.getElementById('uptime').textContent=fmtUp(d.uptime_secs);
  document.getElementById('active').textContent=d.active_tls+' TLS \u00b7 '+d.active_tcp+' TCP';
  let html='';
  if(d.tls_routes.length)html+='<div class="section"><div class="section-header">TLS routes</div><div class="card-list">'+d.tls_routes.map(r=>card(r,'tls')).join('')+'</div></div>';
  if(d.tcp_routes.length)html+='<div class="section"><div class="section-header">TCP routes</div><div class="card-list">'+d.tcp_routes.map(r=>card(r,'tcp')).join('')+'</div></div>';
  document.getElementById('main').innerHTML=html||'<div class="msg">Geen routes</div>';
  d.tls_routes.forEach(rt=>{
    if(rt.enabled_until)_startCountdown('cd-tls-'+esc(rt.hostname),rt.enabled_until);
  });
  d.tcp_routes.forEach(rt=>{
    if(rt.enabled_until)_startCountdown('cd-tcp-'+esc(String(rt.listen_port)),rt.enabled_until);
  });
}

async function tog(cb){
  cb.disabled=true;
  const url=cb.dataset.type==='tls'
    ?'/api/routes/'+encodeURIComponent(cb.dataset.id)+'/toggle'
    :'/api/tcp-routes/'+cb.dataset.id+'/toggle';
  try{
    const r=await fetch(url,{method:'POST'});
    if(!r.ok)throw 0;
    const d=await r.json();
    cb.checked=d.enabled;
    const cdId='cd-'+cb.dataset.type+'-'+cb.dataset.id;
    const timerEl=document.getElementById(cdId);
    if(d.enabled&&d.enabled_until){
      _startCountdown(cdId,d.enabled_until);
    }else{
      if(_cdTimers[cdId]){clearInterval(_cdTimers[cdId]);delete _cdTimers[cdId];}
      if(timerEl)timerEl.textContent='';
    }
    if(tg.HapticFeedback)tg.HapticFeedback.impactOccurred('light');
    toast(d.enabled?'\\u2705 Ingeschakeld':'\\u274C Uitgeschakeld');
    await load();
  }catch{cb.checked=!cb.checked;toast('Toggle mislukt');}
  cb.disabled=false;
}

let _autoRefresh;
function startAutoRefresh(){
  clearInterval(_autoRefresh);
  _autoRefresh=setInterval(load,10000);
}

async function refresh(){
  const b=document.getElementById('btn-refresh');
  b.disabled=true;
  await load();
  b.disabled=false;
}


async function init(){
  if(!tg.initData){await load();startAutoRefresh();return;}
  const r=await fetch('/api/tg-auth',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({init_data:tg.initData})});
  if(!r.ok){const e=await r.json().catch(()=>({}));document.getElementById('main').innerHTML='<div class="msg err">Authenticatie mislukt<br>'+esc(e.error||'')+'</div>';return;}
  await load();
  startAutoRefresh();
}

init();
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
    _is_active = False
    try:
        if not backend.enabled:
            _stats["tcp_rej"][backend.name] = _stats["tcp_rej"].get(backend.name, 0) + 1
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
            asyncio.create_task(_tg_alert_backend(
                backend.name, f"TCP connect timeout ({cfg.connect_timeout}s)", cfg))
            return
        except OSError as exc:
            logger.error(f"[{src}] TCP connect failed → {backend.name}: {exc}")
            asyncio.create_task(_tg_alert_backend(backend.name, f"TCP: {exc}", cfg))
            return
        _stats["tcp_ok"][backend.name] = _stats["tcp_ok"].get(backend.name, 0) + 1
        _stats["active_tcp"] += 1
        _is_active = True
        await asyncio.gather(
            pipe(reader, be_writer, f"{src}→{backend.name}"),
            pipe(be_reader, writer, f"{backend.name}→{src}"),
        )
    except Exception as exc:
        logger.error(f"[{src}] TCP unhandled: {exc.__class__.__name__}: {exc}")
    finally:
        if _is_active:
            _stats["active_tcp"] -= 1
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


def _sync_group(cfg: "Config", source: Backend) -> None:
    """Zet alle routes (TLS + TCP) met dezelfde naam als source naar dezelfde enabled-toestand.
    Elke sibling berekent zijn eigen enabled_until op basis van zijn eigen auto_disable_minutes."""
    now = time.time()
    for b in list(cfg.tls_routes.values()) + list(cfg.tcp_routes.values()):
        if b is source or b.name != source.name:
            continue
        b.enabled = source.enabled
        if b.enabled and b.auto_disable_minutes > 0:
            b.enabled_until = now + b.auto_disable_minutes * 60
        else:
            b.enabled_until = None


def _apply_toggle(backend: Backend, cfg: Optional["Config"] = None) -> None:
    """Toggle backend.enabled en zet/wis enabled_until conform auto_disable_minutes.
    Als cfg meegegeven: synct alle routes met dezelfde naam naar dezelfde toestand."""
    backend.enabled = not backend.enabled
    if backend.enabled and backend.auto_disable_minutes > 0:
        backend.enabled_until = time.time() + backend.auto_disable_minutes * 60
    else:
        backend.enabled_until = None
    if cfg is not None:
        _sync_group(cfg, backend)


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
        if content_length > 65536:
            writer.write(b"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            return
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

        if method == "GET" and path == "/app":
            respond(200, "text/html; charset=utf-8", MINI_APP_HTML.encode("utf-8"))

        elif method == "POST" and path == "/api/tg-auth":
            try:
                data = json.loads(body)
                init_data = str(data.get("init_data", ""))
            except Exception:
                json_resp(400, {"error": "Ongeldige invoer."})
            else:
                bot_token = proxy_server.cfg.telegram.bot_token
                if not bot_token:
                    json_resp(500, {"error": "Telegram niet geconfigureerd."})
                elif not _validate_tg_init_data(init_data, bot_token):
                    json_resp(403, {"error": "Ongeldige of verlopen toegang."})
                else:
                    allowed = proxy_server.cfg.telegram.allowed_chat_ids
                    authorized = False
                    if allowed:
                        try:
                            params = dict(urllib.parse.parse_qsl(init_data, keep_blank_values=True))
                            user_str = params.get("user", "")
                            if not user_str.startswith("{"):
                                raise ValueError("user field is not a JSON object")
                            user_id = json.loads(user_str).get("id")
                            authorized = user_id in allowed
                        except Exception:
                            authorized = False
                    if not authorized:
                        json_resp(403, {"error": "Niet toegestaan."})
                    else:
                        token = _create_session()
                        cookie = (
                            f"proxy_session={token}; Max-Age={SESSION_TTL}; "
                            f"Path=/; HttpOnly; Secure; SameSite=Strict"
                        )
                        json_resp(200, {"ok": True}, [("Set-Cookie", cookie)])

        elif method == "GET" and path == "/favicon.svg":
            respond(200, "image/svg+xml", LOGO_SVG.encode())

        elif method == "GET" and path == "/login":
            respond(200, "text/html; charset=utf-8",
                    _make_login_html(bool(proxy_server.cfg.totp_secret)).encode("utf-8"))

        elif method == "POST" and path == "/api/auth/request-code":
            global _last_code_ts
            now = time.time()
            client_ip = (writer.get_extra_info("peername") or ("?",))[0]
            ip_last = _code_ts_per_ip.get(client_ip, 0.0)
            remaining = CODE_COOLDOWN - (now - max(_last_code_ts, ip_last))
            if remaining > 0:
                json_resp(429, {"error": f"Wacht nog {int(remaining)+1} seconden voor een nieuwe code."})
            elif not proxy_server.cfg.email.gmail_user and not proxy_server.cfg.telegram.bot_token:
                json_resp(500, {"error": "Geen e-mail of Telegram geconfigureerd in config.json."})
            else:
                code = _generate_otp()
                _last_code_ts = now
                _code_ts_per_ip[client_ip] = now
                sent_via = []
                errors = []
                if proxy_server.cfg.email.gmail_user:
                    try:
                        await send_otp_email(code, proxy_server.cfg.email)
                        logger.info(f"OTP-code verstuurd naar {proxy_server.cfg.email.to}")
                        sent_via.append("e-mail")
                    except Exception as exc:
                        logger.error(f"E-mail versturen mislukt: {exc}")
                        errors.append("e-mail")
                if proxy_server.cfg.telegram.bot_token:
                    try:
                        await _tg_send_otp(code, proxy_server.cfg)
                        logger.info("OTP-code verstuurd via Telegram")
                        sent_via.append("Telegram")
                    except Exception as exc:
                        logger.error(f"Telegram OTP versturen mislukt: {exc}")
                        errors.append("Telegram")
                if sent_via:
                    json_resp(200, {"ok": True})
                else:
                    json_resp(500, {"error": f"Versturen mislukt via: {', '.join(errors)}"})

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

        elif method == "POST" and path == "/api/auth/verify-totp":
            if not proxy_server.cfg.totp_secret:
                json_resp(400, {"error": "TOTP is niet geconfigureerd."})
            else:
                try:
                    data = json.loads(body)
                    code = str(data.get("code", "")).strip()
                except Exception:
                    json_resp(400, {"error": "Ongeldige invoer."})
                else:
                    if not code.isdigit() or len(code) != 6:
                        json_resp(400, {"error": "Code moet 6 cijfers zijn."})
                    elif _totp_verify(code, proxy_server.cfg.totp_secret, window=2):
                        token = _create_session()
                        cookie = (
                            f"proxy_session={token}; Max-Age={SESSION_TTL}; "
                            f"Path=/; HttpOnly; Secure; SameSite=Strict"
                        )
                        logger.info("Succesvolle inlog via TOTP")
                        json_resp(200, {"ok": True}, [("Set-Cookie", cookie)])
                    else:
                        json_resp(401, {"error": "Ongeldige of al gebruikte code."})

        elif method == "POST" and path == "/api/auth/logout":
            if session_token and session_token in _sessions:
                del _sessions[session_token]
            clear_cookie = "proxy_session=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Strict"
            json_resp(200, {"ok": True}, [("Set-Cookie", clear_cookie)])

        # ── TOTP beheer (sessie vereist) ──────────────────────────────────────

        elif method == "GET" and path == "/totp-setup":
            if not authed:
                redirect("/login")
            else:
                respond(200, "text/html; charset=utf-8", TOTP_SETUP_HTML.encode("utf-8"))

        elif method == "GET" and path == "/api/totp/new-secret":
            if not authed:
                json_resp(401, {"error": "Niet ingelogd."})
            else:
                new_secret = _totp_new_secret()
                uri = _totp_uri(new_secret)
                resp = {"secret": new_secret, "uri": uri}
                qr = _totp_qr_svg(uri)
                if qr:
                    resp["qr_svg"] = qr
                json_resp(200, resp)

        elif method == "POST" and path == "/api/totp/enable":
            if not authed:
                json_resp(401, {"error": "Niet ingelogd."})
            else:
                try:
                    data   = json.loads(body)
                    secret = str(data.get("secret", "")).strip().upper().replace(" ", "")
                    code   = str(data.get("code", "")).strip()
                except Exception:
                    json_resp(400, {"error": "Ongeldige invoer."})
                else:
                    if not secret or not code.isdigit() or len(code) != 6:
                        json_resp(400, {"error": "Geef een geldig geheim en 6-cijferige code."})
                    else:
                        try:
                            base64.b32decode(secret)   # valideer base32
                            ok = _totp_verify(code, secret)
                        except Exception:
                            ok = False
                        if ok:
                            proxy_server.cfg.totp_secret = secret
                            save_config(proxy_server.cfg, proxy_server.config_path)
                            logger.info("TOTP geactiveerd")
                            json_resp(200, {"ok": True})
                        else:
                            json_resp(400, {"error": "Code klopt niet bij dit geheim. Probeer opnieuw."})

        elif method == "POST" and path == "/api/totp/disable":
            if not authed:
                json_resp(401, {"error": "Niet ingelogd."})
            else:
                proxy_server.cfg.totp_secret = ""
                save_config(proxy_server.cfg, proxy_server.config_path)
                logger.info("TOTP uitgeschakeld")
                json_resp(200, {"ok": True})

        elif method == "GET" and path == "/api/totp/status":
            if not authed:
                json_resp(401, {"error": "Niet ingelogd."})
            else:
                json_resp(200, {"enabled": bool(proxy_server.cfg.totp_secret)})

        # ── Beveiligde routes (sessie vereist) ────────────────────────────────

        elif method == "GET" and path == "/":
            if not authed:
                redirect("/login")
            else:
                respond(200, "text/html; charset=utf-8", ADMIN_HTML.encode("utf-8"))

        elif not authed:
            json_resp(401, {"error": "Niet ingelogd."})

        elif method == "GET" and path == "/api/overview":
            uptime = int(time.time() - _stats["since"]) if _stats["since"] else 0
            json_resp(200, {
                "uptime_secs": uptime,
                "active_tls":  _stats["active_tls"],
                "active_tcp":  _stats["active_tcp"],
                "tls_routes": [
                    {"hostname": h, "host": b.host, "port": b.port, "name": b.name,
                     "enabled": b.enabled,
                     "auto_disable_minutes": b.auto_disable_minutes,
                     "enabled_until": b.enabled_until,
                     "ok":       _stats["tls_ok"].get(h, 0),
                     "rejected": _stats["tls_rej"].get(h, 0)}
                    for h, b in proxy_server.cfg.tls_routes.items()
                ],
                "tcp_routes": [
                    {"listen_port": p, "host": b.host, "port": b.port, "name": b.name,
                     "enabled": b.enabled,
                     "auto_disable_minutes": b.auto_disable_minutes,
                     "enabled_until": b.enabled_until,
                     "ok":       _stats["tcp_ok"].get(b.name, 0),
                     "rejected": _stats["tcp_rej"].get(b.name, 0)}
                    for p, b in proxy_server.cfg.tcp_routes.items()
                ],
                "unknown_sni": _stats["tls_unknown"],
            })

        elif method == "POST" and path == "/api/reload":
            proxy_server.reload()
            json_resp(200, {"ok": True})

        elif method == "POST" and path == "/api/stats/clear":
            _stats["tls_ok"].clear()
            _stats["tls_rej"].clear()
            _stats["tcp_ok"].clear()
            _stats["tcp_rej"].clear()
            _stats["tls_unknown"] = 0
            logger.info("Statistieken gereset via admin UI")
            json_resp(200, {"ok": True})

        elif method == "GET" and path == "/api/routes":
            routes = [
                {"hostname": h, "host": b.host, "port": b.port, "name": b.name, "enabled": b.enabled,
                 "tls_terminate": b.tls_terminate,
                 "auto_disable_minutes": b.auto_disable_minutes,
                 "enabled_until": b.enabled_until,
                 "ok": _stats["tls_ok"].get(h, 0), "rejected": _stats["tls_rej"].get(h, 0)}
                for h, b in proxy_server.cfg.tls_routes.items()
            ]
            respond(200, "application/json", json.dumps(routes).encode())

        elif method == "POST" and path == "/api/routes":
            try:
                data = json.loads(body)
                hostname      = data["hostname"].strip().lower()
                host          = data["host"].strip()
                port          = int(data["port"])
                name          = data["name"].strip()
                tls_terminate = bool(data.get("tls_terminate", False))
                if not hostname or not host or not name or not (1 <= port <= 65535):
                    raise ValueError("invalid fields")
            except Exception:
                json_resp(400, {"error": "Ongeldige invoer."})
            else:
                if hostname in proxy_server.cfg.tls_routes:
                    json_resp(400, {"error": "Hostname bestaat al."})
                else:
                    proxy_server.cfg.tls_routes[hostname] = Backend(
                        host=host, port=port, name=name, tls_terminate=tls_terminate,
                    )
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

        elif method == "POST" and path.startswith("/api/routes/") and path.endswith("/auto-disable"):
            segments = path.strip("/").split("/")
            if len(segments) == 4:
                hostname = urllib.parse.unquote(segments[2])
                backend  = proxy_server.cfg.tls_routes.get(hostname)
                if backend is None:
                    json_resp(404, {"error": "Route niet gevonden."})
                else:
                    try:
                        minutes = int(json.loads(body).get("minutes", 0))
                        if minutes < 0:
                            raise ValueError
                    except Exception:
                        json_resp(400, {"error": "Ongeldige waarde voor minutes."})
                    else:
                        backend.auto_disable_minutes = minutes
                        if backend.enabled and minutes > 0 and backend.enabled_until is None:
                            backend.enabled_until = time.time() + minutes * 60
                        elif minutes == 0:
                            backend.enabled_until = None
                        save_config(proxy_server.cfg, proxy_server.config_path)
                        json_resp(200, {"hostname": hostname, "auto_disable_minutes": minutes,
                                        "enabled_until": backend.enabled_until})
            else:
                json_resp(400, {"error": "Ongeldig verzoek."})

        elif method == "POST" and path.startswith("/api/tcp-routes/") and path.endswith("/auto-disable"):
            try:
                listen_port = int(path.strip("/").split("/")[2])
            except (ValueError, IndexError):
                json_resp(400, {"error": "Ongeldige poort."})
            else:
                backend = proxy_server.cfg.tcp_routes.get(listen_port)
                if backend is None:
                    json_resp(404, {"error": "TCP route niet gevonden."})
                else:
                    try:
                        minutes = int(json.loads(body).get("minutes", 0))
                        if minutes < 0:
                            raise ValueError
                    except Exception:
                        json_resp(400, {"error": "Ongeldige waarde voor minutes."})
                    else:
                        backend.auto_disable_minutes = minutes
                        if backend.enabled and minutes > 0 and backend.enabled_until is None:
                            backend.enabled_until = time.time() + minutes * 60
                        elif minutes == 0:
                            backend.enabled_until = None
                        save_config(proxy_server.cfg, proxy_server.config_path)
                        json_resp(200, {"listen_port": listen_port, "auto_disable_minutes": minutes,
                                        "enabled_until": backend.enabled_until})

        elif method == "POST" and path.startswith("/api/routes/") and path.endswith("/toggle"):
            segments = path.strip("/").split("/")
            if len(segments) == 4 and segments[0] == "api" and segments[1] == "routes":
                hostname = urllib.parse.unquote(segments[2])
                backend  = proxy_server.cfg.tls_routes.get(hostname)
                if backend is None:
                    json_resp(404, {"error": "Route niet gevonden."})
                else:
                    _apply_toggle(backend, proxy_server.cfg)
                    save_config(proxy_server.cfg, proxy_server.config_path)
                    state = "ingeschakeld" if backend.enabled else "uitgeschakeld"
                    logger.info(f"Route {hostname} {state} via admin UI")
                    json_resp(200, {"hostname": hostname, "enabled": backend.enabled,
                                    "enabled_until": backend.enabled_until})
            else:
                json_resp(400, {"error": "Ongeldig verzoek."})

        elif method == "GET" and path == "/api/tcp-routes":
            routes = [
                {"listen_port": p, "host": b.host, "port": b.port, "name": b.name, "enabled": b.enabled,
                 "auto_disable_minutes": b.auto_disable_minutes,
                 "enabled_until": b.enabled_until,
                 "ok": _stats["tcp_ok"].get(b.name, 0), "rejected": _stats["tcp_rej"].get(b.name, 0)}
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
                    _apply_toggle(backend, proxy_server.cfg)
                    save_config(proxy_server.cfg, proxy_server.config_path)
                    state = "ingeschakeld" if backend.enabled else "uitgeschakeld"
                    logger.info(f"TCP route :{listen_port} {state} via admin UI")
                    json_resp(200, {"listen_port": listen_port, "enabled": backend.enabled,
                                    "enabled_until": backend.enabled_until})

        else:
            respond(404, "text/plain", b"Not found")

        try:
            await writer.drain()
        except Exception as drain_exc:
            logger.warning(f"Admin drain fout [{method} {path}]: {drain_exc}")
            break

    except Exception as exc:
        logger.warning(f"Admin handler error: {exc}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


# ── Telegram bot ─────────────────────────────────────────────────────────────

def _tg_call(token: str, method: str, params: dict | None = None, timeout: int = 35) -> dict:
    """Blocking Telegram API call — gebruik via asyncio.to_thread."""
    url = f"https://api.telegram.org/bot{token}/{method}"
    data = json.dumps(params or {}).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        raise RuntimeError(f"Telegram {method} HTTP {exc.code}: {body}") from exc


async def _tg_broadcast(token: str, allowed_ids: list, text: str) -> None:
    """Stuur een bericht naar alle toegestane chat-IDs."""
    for chat_id in allowed_ids:
        try:
            await asyncio.to_thread(_tg_call, token, "sendMessage", {
                "chat_id": chat_id, "text": text, "parse_mode": "HTML",
            })
        except Exception as exc:
            logger.warning(f"Telegram broadcast naar {chat_id} mislukt: {exc}")


def _cert_expiry(cert_path: str) -> Optional[datetime]:
    """Geeft de vervaldatum van een PEM-certificaat terug via openssl."""
    try:
        result = subprocess.run(
            ["openssl", "x509", "-noout", "-enddate", "-in", cert_path],
            capture_output=True, text=True, timeout=5,
        )
        date_str = result.stdout.strip().split("=", 1)[1]
        return datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except Exception:
        return None


def _fmt_uptime(since: float) -> str:
    secs = max(0, int(time.time() - since))
    h, rem = divmod(secs, 3600)
    m = rem // 60
    return f"{h}u {m}m" if h else f"{m}m"


def _tg_status_text(cfg: "Config") -> str:
    uptime = _fmt_uptime(_stats["since"]) if _stats["since"] else "?"
    lines = [
        f"<b>Proxy</b> — uptime {uptime}",
        f"Actief: {_stats['active_tls']} TLS · {_stats['active_tcp']} TCP",
    ]

    if cfg.tls_routes:
        lines.append("")
        lines.append("<b>TLS routes</b>")
        for hostname, be in cfg.tls_routes.items():
            icon = "✅" if be.enabled else "❌"
            ok  = _stats["tls_ok"].get(hostname, 0)
            rej = _stats["tls_rej"].get(hostname, 0)
            stat = f"{ok} verbindingen" + (f", {rej} geweigerd" if rej else "")
            lines.append(f"{icon} <b>{be.name}</b>  <code>{hostname}</code>  {stat}")

    if cfg.tcp_routes:
        lines.append("")
        lines.append("<b>TCP routes</b>")
        for port, be in cfg.tcp_routes.items():
            icon = "✅" if be.enabled else "❌"
            ok  = _stats["tcp_ok"].get(be.name, 0)
            rej = _stats["tcp_rej"].get(be.name, 0)
            stat = f"{ok} verbindingen" + (f", {rej} geweigerd" if rej else "")
            lines.append(f"{icon} <b>{be.name}</b>  <code>:{port}</code>  {stat}")

    if _stats["tls_unknown"]:
        lines.append(f"\n⚠️ Onbekende SNI: {_stats['tls_unknown']}×")

    return "\n".join(lines)


def _tg_toggle_keyboard(cfg: "Config") -> dict:
    """Inline keyboard met Mini App knop bovenaan en toggle-knoppen per route."""
    rows = []
    if cfg.telegram.mini_app_url:
        rows.append([{"text": "📱 Beheer openen", "web_app": {"url": cfg.telegram.mini_app_url}}])
    for hostname, be in cfg.tls_routes.items():
        icon = "✅" if be.enabled else "❌"
        rows.append([{"text": f"{icon} {be.name}", "callback_data": f"tls:{hostname}"[:64]}])
    for port, be in cfg.tcp_routes.items():
        icon = "✅" if be.enabled else "❌"
        rows.append([{"text": f"{icon} {be.name} (TCP)", "callback_data": f"tcp:{port}"}])
    return {"inline_keyboard": rows}


async def _tg_send_status(token: str, chat_id: int, cfg: "Config") -> None:
    await asyncio.to_thread(_tg_call, token, "sendMessage", {
        "chat_id": chat_id,
        "text": _tg_status_text(cfg),
        "parse_mode": "HTML",
        "reply_markup": _tg_toggle_keyboard(cfg),
    })


async def _tg_edit_status(token: str, chat_id: int, message_id: int, cfg: "Config") -> None:
    await asyncio.to_thread(_tg_call, token, "editMessageText", {
        "chat_id": chat_id,
        "message_id": message_id,
        "text": _tg_status_text(cfg),
        "parse_mode": "HTML",
        "reply_markup": _tg_toggle_keyboard(cfg),
    })


async def _tg_alert_backend(name: str, error: str, cfg: "Config") -> None:
    """Stuur een backend-alert (maximaal één per 5 minuten per backend)."""
    if not cfg.telegram.bot_token:
        return
    now = time.time()
    if now - _alert_cooldowns.get(name, 0) < _ALERT_COOLDOWN:
        return
    _alert_cooldowns[name] = now
    await _tg_broadcast(cfg.telegram.bot_token, cfg.telegram.allowed_chat_ids,
                        f"⚠️ <b>Backend onbereikbaar</b>\n\n<b>{name}</b>: {error}")


async def _tg_notify_connect(sni: str, backend: "Backend", src: str, cfg: "Config") -> None:
    """Stuur een verbindingsnotificatie voor routes met notify=true."""
    ip = src.rsplit(":", 1)[0]  # haal poortnummer weg, houd IP over
    await _tg_broadcast(cfg.telegram.bot_token, cfg.telegram.allowed_chat_ids,
                        f"🔔 <b>{backend.name}</b>  {ip}")


async def _tg_cmd_cert(token: str, chat_id: int, cfg: "Config") -> None:
    """Toon vervaldatums van alle geconfigureerde certificaten."""
    now = datetime.now(timezone.utc)
    certs: list[tuple[str, str]] = []
    seen: set[str] = set()
    if cfg.tls_cert and cfg.tls_cert not in seen:
        certs.append(("Wildcard", cfg.tls_cert))
        seen.add(cfg.tls_cert)
    for be in cfg.tls_routes.values():
        if be.tls_cert and be.tls_cert not in seen:
            certs.append((be.name, be.tls_cert))
            seen.add(be.tls_cert)

    lines = ["<b>Certificaten</b>\n"]
    for label, path in certs:
        expiry = await asyncio.to_thread(_cert_expiry, path)
        if expiry:
            days = (expiry - now).days
            icon = "🔴" if days <= 14 else ("🟡" if days <= 30 else "🟢")
            lines.append(f"{icon} <b>{label}</b> — {days} dagen  ({expiry.strftime('%d %b %Y')})")
        else:
            lines.append(f"❓ <b>{label}</b> — onbekend")

    await asyncio.to_thread(_tg_call, token, "sendMessage", {
        "chat_id": chat_id, "text": "\n".join(lines), "parse_mode": "HTML",
    })


_SENSITIVE_LOG_RE = re.compile(r'password|passwd|secret|token|key\b', re.IGNORECASE)


async def _tg_cmd_logs(token: str, chat_id: int) -> None:
    """Stuur de laatste 30 logregels."""
    result = await asyncio.to_thread(
        subprocess.run,
        ["journalctl", "-u", "py-proxy", "-n", "30", "--no-pager", "--output=short"],
        capture_output=True, text=True, timeout=10,
    )
    lines = [l for l in result.stdout.splitlines() if not _SENSITIVE_LOG_RE.search(l)]
    text = "\n".join(lines).strip() or "(geen logs)"
    if len(text) > 3900:
        text = "…\n" + text[-3900:]
    await asyncio.to_thread(_tg_call, token, "sendMessage", {
        "chat_id": chat_id,
        "text": f"<pre>{html.escape(text)}</pre>",
        "parse_mode": "HTML",
    })


async def _tg_send_otp(code: str, cfg: "Config") -> None:
    """Stuur OTP-code naar alle toegestane Telegram chat-IDs."""
    token = cfg.telegram.bot_token
    if not token:
        return
    text = (
        f"🔐 <b>Inlogcode admin UI</b>\n\n"
        f"<code>{code}</code>\n\n"
        f"Geldig 5 minuten. Eenmalig bruikbaar."
    )
    for chat_id in cfg.telegram.allowed_chat_ids:
        await asyncio.to_thread(_tg_call, token, "sendMessage", {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML",
        })


async def _tg_handle_message(
    message: dict, token: str, allowed_ids: list, proxy: "ProxyServer",
    update_id: int = None,
) -> None:
    chat_id = message["chat"]["id"]
    if allowed_ids and chat_id not in allowed_ids:
        logger.warning(f"Telegram: bericht van niet-toegestane chat_id {chat_id}")
        return
    text = message.get("text", "").strip()
    if not text.startswith("/"):
        return
    command = text.split()[0].lower().split("@")[0]
    if command == "/status":
        await _tg_send_status(token, chat_id, proxy.cfg)
    elif command == "/start":
        await asyncio.to_thread(_tg_call, token, "sendMessage", {
            "chat_id": chat_id,
            "text": "🟢 <b>SNI Proxy</b> actief. Gebruik /status voor routes en toggle-knoppen.",
            "parse_mode": "HTML",
        })
    elif command == "/help":
        await asyncio.to_thread(_tg_call, token, "sendMessage", {
            "chat_id": chat_id,
            "text": (
                "<b>Commando's</b>\n\n"
                "/status — routes, statistieken en toggle-knoppen\n"
                "/cert   — vervaldatums van alle certificaten\n"
                "/logs   — laatste 30 logregels\n"
                "/reload  — config herladen (zonder herstart)\n"
                "/restart — service herstarten\n"
                "/clear   — verbindingstellers resetten\n"
                "/proxyaan — proxy.budie.eu inschakelen\n"
                "/proxyuit — proxy.budie.eu uitschakelen\n"
                "/help   — dit bericht"
            ),
            "parse_mode": "HTML",
        })
    elif command == "/cert":
        await _tg_cmd_cert(token, chat_id, proxy.cfg)
    elif command == "/logs":
        await _tg_cmd_logs(token, chat_id)
    elif command == "/reload":
        proxy.reload()
        await asyncio.to_thread(_tg_call, token, "sendMessage", {
            "chat_id": chat_id, "text": "✅ Config herladen.",
        })
    elif command == "/restart":
        await asyncio.to_thread(_tg_call, token, "sendMessage", {
            "chat_id": chat_id, "text": "🔄 Service herstarten…",
        })
        # Bevestig deze update bij Telegram zodat de nieuwe instantie hem niet opnieuw verwerkt
        if update_id is not None:
            try:
                await asyncio.to_thread(
                    _tg_call, token, "getUpdates", {"offset": update_id + 1, "timeout": 0}, 5
                )
            except Exception:
                pass
        logger.info("Telegram: service herstart via /restart")
        proc = await asyncio.create_subprocess_exec(
            "sudo", "systemctl", "restart", "py-proxy",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.wait()
    elif command == "/clear":
        _stats["tls_ok"].clear()
        _stats["tls_rej"].clear()
        _stats["tcp_ok"].clear()
        _stats["tcp_rej"].clear()
        _stats["tls_unknown"] = 0
        logger.info("Telegram: statistieken gereset via /clear")
        await asyncio.to_thread(_tg_call, token, "sendMessage", {
            "chat_id": chat_id, "text": "✅ Tellers gereset.",
        })
    elif command in ("/proxyaan", "/proxyuit"):
        backend = proxy.cfg.tls_routes.get("proxy.budie.eu")
        if not backend:
            await asyncio.to_thread(_tg_call, token, "sendMessage", {
                "chat_id": chat_id, "text": "⚠️ Route proxy.budie.eu niet gevonden in config.",
            })
        else:
            new_enabled = command == "/proxyaan"
            if backend.enabled != new_enabled:
                _apply_toggle(backend, proxy.cfg)
            save_config(proxy.cfg, proxy.config_path)
            state = "ingeschakeld" if backend.enabled else "uitgeschakeld"
            icon  = "✅" if backend.enabled else "❌"
            logger.info(f"Telegram: proxy.budie.eu {state} via {command}")
            await asyncio.to_thread(_tg_call, token, "sendMessage", {
                "chat_id": chat_id, "text": f"{icon} proxy.budie.eu {state}.",
            })
    else:
        await asyncio.to_thread(_tg_call, token, "sendMessage", {
            "chat_id": chat_id, "text": "Onbekend commando. Gebruik /help.",
        })


async def _tg_handle_callback(
    callback: dict, token: str, allowed_ids: list, proxy: "ProxyServer"
) -> None:
    chat_id    = callback["message"]["chat"]["id"]
    cb_id      = callback["id"]
    message_id = callback["message"]["message_id"]
    data       = callback.get("data", "")

    if allowed_ids and chat_id not in allowed_ids:
        return

    toggled_name: Optional[str] = None
    new_state: Optional[bool]   = None

    if data.startswith("tls:"):
        hostname = data[4:]
        backend  = proxy.cfg.tls_routes.get(hostname)
        if not backend:
            await asyncio.to_thread(_tg_call, token, "answerCallbackQuery",
                                    {"callback_query_id": cb_id, "text": "Route niet gevonden"})
            return
        _apply_toggle(backend, proxy.cfg)
        save_config(proxy.cfg, proxy.config_path)
        state = "ingeschakeld" if backend.enabled else "uitgeschakeld"
        logger.info(f"Telegram: TLS route {hostname} {state}")
        toggled_name, new_state = backend.name, backend.enabled

    elif data.startswith("tcp:"):
        try:
            port = int(data[4:])
        except ValueError:
            return
        backend = proxy.cfg.tcp_routes.get(port)
        if not backend:
            await asyncio.to_thread(_tg_call, token, "answerCallbackQuery",
                                    {"callback_query_id": cb_id, "text": "TCP route niet gevonden"})
            return
        _apply_toggle(backend, proxy.cfg)
        save_config(proxy.cfg, proxy.config_path)
        state = "ingeschakeld" if backend.enabled else "uitgeschakeld"
        logger.info(f"Telegram: TCP route :{port} {state}")
        toggled_name, new_state = backend.name, backend.enabled

    if toggled_name is not None:
        icon = "✅" if new_state else "❌"
        await asyncio.to_thread(_tg_call, token, "answerCallbackQuery", {
            "callback_query_id": cb_id,
            "text": f"{icon} {toggled_name} {'aan' if new_state else 'uit'}",
        })
        try:
            await _tg_edit_status(token, chat_id, message_id, proxy.cfg)
        except Exception as exc:
            logger.debug(f"Telegram: editMessageText mislukt: {exc}")


# ── Server ────────────────────────────────────────────────────────────────────

class ProxyServer:
    def __init__(self, config_path: Path) -> None:
        self.config_path = config_path
        self.cfg = load_config(config_path)
        self._ssl_ctxs: dict[tuple[str, str], ssl.SSLContext] = self._load_ssl_ctxs()
        self._tg_task: Optional[asyncio.Task] = None
        _stats["since"] = time.time()

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
                mode = os.stat(key).st_mode & 0o177
                if mode != 0o600:
                    logger.warning(f"Private key {key} heeft te brede permissies: {oct(0o100000 | mode)}")
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
        old_cfg = self.cfg
        old_ssl_ctxs = self._ssl_ctxs
        try:
            new_cfg = load_config(self.config_path)
            self.cfg = new_cfg
            new_ssl_ctxs = self._load_ssl_ctxs()
            self._ssl_ctxs = new_ssl_ctxs
            log_config(self.cfg)
        except Exception as exc:
            self.cfg = old_cfg
            self._ssl_ctxs = old_ssl_ctxs
            logger.error(f"Config reload failed: {exc} — kept old config")
            return
        # Herstart Telegram bot als het token is gewijzigd
        new_token = self.cfg.telegram.bot_token
        if old_token != new_token:
            if self._tg_task and not self._tg_task.done():
                self._tg_task.cancel()
            if new_token:
                self._tg_task = asyncio.create_task(self._telegram_bot_loop())

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

        for listen_port in list(self.cfg.tcp_routes):
            def tcp_handler(r, w, port=listen_port):
                backend = self.cfg.tcp_routes.get(port)
                if backend is None:
                    w.close()
                    return asyncio.create_task(asyncio.sleep(0))
                return asyncio.create_task(handle_tcp_connection(r, w, backend, self.cfg))
            srv = await asyncio.start_server(tcp_handler, self.cfg.listen_host, listen_port)
            self._servers.append(srv)
            be = self.cfg.tcp_routes[listen_port]
            logger.info(f"TCP route :{listen_port} → {be.name} ({be.host}:{be.port})")

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

        if self.cfg.telegram.bot_token:
            self._tg_task = asyncio.create_task(self._telegram_bot_loop())
            self._daily_task = asyncio.create_task(self._daily_task_loop())
            logger.info("Telegram bot gestart")
        else:
            self._daily_task = None
            logger.info("Telegram bot niet geconfigureerd (geen bot_token in config.json)")

        asyncio.create_task(self._cleanup_task_loop())
        asyncio.create_task(self._auto_disable_task_loop())
        await asyncio.gather(*(srv.serve_forever() for srv in self._servers))

    async def _cleanup_task_loop(self) -> None:
        """Ruim verlopen OTP-codes en sessies elke 60 seconden op."""
        while True:
            await asyncio.sleep(60)
            _cleanup_expired()

    async def _auto_disable_task_loop(self) -> None:
        """Schakel routes uit die hun auto_disable timer hebben overschreden."""
        while True:
            await asyncio.sleep(15)
            try:
                now = time.time()
                disabled: list[str] = []
                for hostname, backend in self.cfg.tls_routes.items():
                    if backend.enabled and backend.enabled_until is not None and now >= backend.enabled_until:
                        backend.enabled = False
                        backend.enabled_until = None
                        _sync_group(self.cfg, backend)
                        disabled.append(f"TLS:{hostname}")
                        logger.info(f"Route {hostname} automatisch uitgeschakeld (auto_disable_minutes={backend.auto_disable_minutes})")
                for port, backend in self.cfg.tcp_routes.items():
                    if backend.enabled and backend.enabled_until is not None and now >= backend.enabled_until:
                        backend.enabled = False
                        backend.enabled_until = None
                        _sync_group(self.cfg, backend)
                        disabled.append(f"TCP:{port}")
                        logger.info(f"TCP route :{port} automatisch uitgeschakeld (auto_disable_minutes={backend.auto_disable_minutes})")
                if disabled:
                    save_config(self.cfg, self.config_path)
                    token = self.cfg.telegram.bot_token
                    if token:
                        names = ", ".join(disabled)
                        await _tg_broadcast(token, self.cfg.telegram.allowed_chat_ids,
                                            f"⏱ <b>Auto-uitgeschakeld</b>: {names}")
            except Exception as exc:
                logger.warning(f"_auto_disable_task_loop fout: {exc}")

    async def _daily_task_loop(self) -> None:
        """Dagelijks om 08:00 UTC: stuur statussamenvatting en check cert-vervaldatums."""
        from datetime import timedelta
        while True:
            try:
                now = datetime.now(timezone.utc)
                next_run = now.replace(hour=8, minute=0, second=0, microsecond=0)
                if next_run <= now:
                    next_run += timedelta(days=1)
                await asyncio.sleep((next_run - now).total_seconds())

                token = self.cfg.telegram.bot_token
                if not token:
                    continue

                # Cert-vervaldatums controleren
                now_utc = datetime.now(timezone.utc)
                warnings = []
                seen: set[str] = set()
                certs: list[tuple[str, str]] = []
                if self.cfg.tls_cert:
                    certs.append(("Wildcard", self.cfg.tls_cert))
                    seen.add(self.cfg.tls_cert)
                for be in self.cfg.tls_routes.values():
                    if be.tls_cert and be.tls_cert not in seen:
                        certs.append((be.name, be.tls_cert))
                        seen.add(be.tls_cert)
                for label, path in certs:
                    expiry = await asyncio.to_thread(_cert_expiry, path)
                    if expiry:
                        days = (expiry - now_utc).days
                        if days <= 30:
                            icon = "🔴" if days <= 14 else "🟡"
                            warnings.append(f"{icon} <b>{label}</b>: verloopt over {days} dagen")
                if warnings:
                    await _tg_broadcast(token, self.cfg.telegram.allowed_chat_ids,
                                        "⚠️ <b>Certificaten verlopen binnenkort</b>\n\n" + "\n".join(warnings))
            except asyncio.CancelledError:
                return
            except Exception as exc:
                logger.warning(f"Dagelijkse taak fout: {exc}")
                await asyncio.sleep(3600)

    async def _telegram_bot_loop(self) -> None:
        offset = 0
        token   = self.cfg.telegram.bot_token
        allowed = self.cfg.telegram.allowed_chat_ids

        # Stel menu-knop in zodat de Mini App direct opent zonder commando
        if self.cfg.telegram.mini_app_url:
            try:
                await asyncio.to_thread(_tg_call, token, "setMyDefaultMenuButton", {
                    "menu_button": {
                        "type": "web_app",
                        "text": "Beheer",
                        "web_app": {"url": self.cfg.telegram.mini_app_url},
                    }
                })
                logger.info("Telegram menu-knop ingesteld")
            except Exception as exc:
                logger.warning(f"Telegram menu-knop instellen mislukt: {exc}")

        # Opstartmelding
        try:
            await _tg_broadcast(token, allowed, "🟢 <b>Proxy gestart</b>")
        except Exception as exc:
            logger.warning(f"Telegram opstartmelding mislukt: {exc}")
        while True:
            try:
                token      = self.cfg.telegram.bot_token
                allowed    = self.cfg.telegram.allowed_chat_ids
                result     = await asyncio.to_thread(
                    _tg_call, token, "getUpdates",
                    {"offset": offset, "timeout": 5}, 10,
                )
                for update in result.get("result", []):
                    offset = update["update_id"] + 1
                    try:
                        if "message" in update or "edited_message" in update:
                            msg = update.get("message") or update["edited_message"]
                            await _tg_handle_message(msg, token, allowed, self, update["update_id"])
                        elif "callback_query" in update:
                            await _tg_handle_callback(update["callback_query"], token, allowed, self)
                    except Exception as exc:
                        logger.error(f"Telegram update {update.get('update_id')} fout: {exc}")
            except asyncio.CancelledError:
                logger.info("Telegram bot gestopt")
                return
            except Exception as exc:
                logger.warning(f"Telegram polling fout: {exc} — wacht 10s")
                await asyncio.sleep(10)

    def _stop_all(self) -> None:
        for srv in getattr(self, "_servers", []):
            srv.close()
        for task in (self._tg_task, getattr(self, "_daily_task", None)):
            if task and not task.done():
                task.cancel()


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
