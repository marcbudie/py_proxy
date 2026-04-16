#!/usr/bin/env python3
"""Test TOTP verificatie tegen het opgeslagen secret in config.json."""
import base64, hmac, struct, time, json, sys, getpass

# ── Laad secret ──────────────────────────────────────────────────────────────
config_path = "/opt/py_proxy/config.json"
try:
    cfg = json.load(open(config_path))
    secret = cfg.get("totp_secret", "")
    if not secret:
        print("Geen totp_secret in config.json — TOTP is niet ingesteld.")
        sys.exit(1)
    print(f"Secret geladen uit {config_path} ({len(secret)} tekens)")
except PermissionError:
    print(f"Geen leesrechten op {config_path}, voer uit met sudo of geef het secret handmatig in.")
    secret = input("Secret (base32): ").strip().upper().replace(" ", "")
except FileNotFoundError:
    print(f"{config_path} niet gevonden.")
    sys.exit(1)


def totp_code(secret_b32: str, step: int) -> str:
    key = base64.b32decode(secret_b32.upper())
    msg = struct.pack(">Q", step)
    h = hmac.new(key, msg, "sha1").digest()
    offset = h[-1] & 0x0F
    code = struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFF_FFFF
    return f"{code % 1_000_000:06d}"


# ── Toon verwachte codes ──────────────────────────────────────────────────────
step = int(time.time() // 30)
remaining = 30 - (int(time.time()) % 30)
print(f"\nHuidige time-step: {step}  (nog {remaining}s geldig)")
print(f"  vorige  (step-1): {totp_code(secret, step - 1)}")
print(f"  huidig  (step  ): {totp_code(secret, step)}")
print(f"  volgende(step+1): {totp_code(secret, step + 1)}")

# ── Verificatie ───────────────────────────────────────────────────────────────
print()
code = input("Voer de code in uit je app: ").strip()
if len(code) != 6 or not code.isdigit():
    print("Ongeldige invoer — moet 6 cijfers zijn.")
    sys.exit(1)

matched = None
for delta in range(-1, 2):
    s = step + delta
    if totp_code(secret, s) == code:
        matched = delta
        break

if matched is not None:
    label = {-1: "vorige window (−30s)", 0: "huidig window", 1: "volgende window (+30s)"}[matched]
    print(f"✓  Code KLOPT — {label}")
else:
    print("✗  Code klopt NIET in ±1 window. Zoek in groter bereik (±10 min)...")
    found_at = None
    for delta in range(-20, 21):
        if totp_code(secret, step + delta) == code:
            found_at = delta
            break
    if found_at is not None:
        offset_sec = found_at * 30
        print(f"   Code gevonden op delta={found_at:+d} ({offset_sec:+d}s) — telefoonklok loopt {abs(offset_sec)}s {'achter' if offset_sec > 0 else 'voor'}.")
    else:
        print(f"   Code niet gevonden in ±10 minuten — secret in app komt niet overeen met config.json.")
        print(f"   Verwacht voor huidig window: {totp_code(secret, step)}")
