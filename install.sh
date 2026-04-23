#!/usr/bin/env bash
# install.sh — installeer of update py-proxy via systemd of als Podman container.
# Gebruik:
#   sudo bash install.sh              # interactieve keuze
#   sudo bash install.sh --systemd   # altijd systemd
#   sudo bash install.sh --container # altijd container

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="/opt/py_proxy"
SERVICE_NAME="py-proxy"
SYSTEMD_DIR="/etc/systemd/system"
SERVICE_USER="pyproxy"

# ── Keuze installatiemodus ────────────────────────────────────────────────────

MODE=""
if [[ $# -ge 1 ]]; then
    case "$1" in
        --systemd)   MODE="systemd" ;;
        --container) MODE="container" ;;
        *)
            echo "Onbekende optie: $1"
            echo "Gebruik: sudo $0 [--systemd|--container]"
            exit 1
            ;;
    esac
fi

if [[ -z "$MODE" ]]; then
    echo "Kies installatiemodus:"
    echo "  1) systemd  — draait als systeemservice onder gebruiker 'pyproxy'"
    echo "  2) container — draait als Podman container op het host network"
    echo ""
    read -rp "Keuze [1/2]: " _keuze
    case "$_keuze" in
        1) MODE="systemd" ;;
        2) MODE="container" ;;
        *) echo "Ongeldige keuze."; exit 1 ;;
    esac
fi

if [[ $EUID -ne 0 ]]; then
    echo "Dit script moet als root worden uitgevoerd. Gebruik: sudo $0"
    exit 1
fi

echo ""
echo "════════════════════════════════════════"
echo "  py-proxy — modus: $MODE"
echo "════════════════════════════════════════"
echo ""

# ── Gedeeld: config.json naar DEPLOY_DIR ─────────────────────────────────────

_ensure_config() {
    mkdir -p "$DEPLOY_DIR"
    if [[ ! -f "$DEPLOY_DIR/config.json" ]]; then
        if [[ -f "$SCRIPT_DIR/config.json" ]]; then
            cp "$SCRIPT_DIR/config.json" "$DEPLOY_DIR/config.json"
            echo "config.json gekopieerd naar $DEPLOY_DIR."
        else
            echo "LET OP: $DEPLOY_DIR/config.json bestaat nog niet."
            echo "        Maak deze handmatig aan voor de service te starten."
        fi
    else
        echo "config.json al aanwezig in $DEPLOY_DIR — niet overschreven."
    fi
}

# ── Systemd ───────────────────────────────────────────────────────────────────

if [[ "$MODE" == "systemd" ]]; then

    echo "=== [1/6] Systeemgebruiker aanmaken ==="
    if ! id "$SERVICE_USER" &>/dev/null; then
        useradd --system --no-create-home --shell /sbin/nologin "$SERVICE_USER"
        echo "Gebruiker '$SERVICE_USER' aangemaakt."
    else
        echo "Gebruiker '$SERVICE_USER' bestaat al."
    fi

    echo ""
    echo "=== [2/6] Python-dependencies installeren ==="
    if [[ -f "$SCRIPT_DIR/requirements.txt" ]]; then
        pip3 install --quiet --break-system-packages -r "$SCRIPT_DIR/requirements.txt" \
            && echo "Dependencies geïnstalleerd." \
            || echo "WAARSCHUWING: pip install mislukt — segno (QR-code) mogelijk niet beschikbaar."
    fi

    echo ""
    echo "=== [3/6] Bestanden deployen naar $DEPLOY_DIR ==="
    mkdir -p "$DEPLOY_DIR"
    cp "$SCRIPT_DIR/proxy.py" "$DEPLOY_DIR/proxy.py"
    echo "proxy.py gekopieerd."
    _ensure_config

    chown -R "$SERVICE_USER:$SERVICE_USER" "$DEPLOY_DIR"
    chmod 750 "$DEPLOY_DIR"
    chmod 640 "$DEPLOY_DIR/proxy.py"
    [[ -f "$DEPLOY_DIR/config.json" ]] && chmod 640 "$DEPLOY_DIR/config.json"

    if command -v restorecon &>/dev/null; then
        restorecon -R "$DEPLOY_DIR"
        echo "SELinux context hersteld voor $DEPLOY_DIR."
    fi

    echo ""
    echo "--- Traverse-rechten /home/admin instellen ---"
    if setfacl -m "u:${SERVICE_USER}:x" /home/admin 2>/dev/null; then
        echo "  ACL gezet: pyproxy mag /home/admin inlopen."
    else
        echo "  WAARSCHUWING: kon ACL niet zetten op /home/admin — certs mogelijk niet leesbaar."
    fi

    echo ""
    echo "--- Cert-toegang controleren ---"
    CERT_OK=true
    for certfile in \
        "$(python3 -c "import json; c=json.load(open('$DEPLOY_DIR/config.json')); print(c.get('tls_cert',''))" 2>/dev/null)" \
        "$(python3 -c "import json; c=json.load(open('$DEPLOY_DIR/config.json')); print(c.get('tls_key',''))" 2>/dev/null)"; do
        [[ -z "$certfile" ]] && continue
        if ! sudo -u "$SERVICE_USER" test -r "$certfile" 2>/dev/null; then
            echo "  WAARSCHUWING: $certfile niet leesbaar voor $SERVICE_USER"
            echo "  Fix: setfacl -m u:${SERVICE_USER}:r \"$certfile\""
            CERT_OK=false
        fi
    done
    $CERT_OK && echo "  Alle cert-bestanden zijn leesbaar."

    echo ""
    echo "=== [4/6] Sudoers-regel instellen voor /restart ==="
    SUDOERS_FILE="/etc/sudoers.d/pyproxy-restart"
    SUDOERS_LINE="pyproxy ALL=(root) NOPASSWD: /usr/bin/systemctl restart py-proxy"
    if [[ ! -f "$SUDOERS_FILE" ]] || ! grep -qF "$SUDOERS_LINE" "$SUDOERS_FILE"; then
        echo "$SUDOERS_LINE" > "$SUDOERS_FILE"
        chmod 440 "$SUDOERS_FILE"
        echo "Sudoers-regel aangemaakt: $SUDOERS_FILE"
    else
        echo "Sudoers-regel al aanwezig."
    fi

    echo ""
    echo "=== [5/6] Systemd service installeren ==="
    cp "$SCRIPT_DIR/proxy.service" "${SYSTEMD_DIR}/${SERVICE_NAME}.service"
    chmod 644 "${SYSTEMD_DIR}/${SERVICE_NAME}.service"
    systemctl daemon-reload

    echo ""
    echo "=== [6/6] Service activeren en (her)starten ==="
    systemctl enable "${SERVICE_NAME}.service"
    systemctl restart "${SERVICE_NAME}.service"

    echo ""
    echo "=== Status ==="
    systemctl status "${SERVICE_NAME}.service" --no-pager -l || true

    echo ""
    echo "Klaar. De proxy draait als '${SERVICE_USER}' vanuit ${DEPLOY_DIR}."
    echo ""
    echo "Handige commando's:"
    echo "  systemctl status  ${SERVICE_NAME}     # status bekijken"
    echo "  journalctl -u ${SERVICE_NAME} -f       # logs volgen"
    echo "  systemctl reload  ${SERVICE_NAME}     # config herladen (SIGHUP)"
    echo "  systemctl restart ${SERVICE_NAME}     # herstarten"
    echo "  systemctl stop    ${SERVICE_NAME}     # stoppen"

# ── Container (Podman, beheerd door systemd als root) ─────────────────────────

elif [[ "$MODE" == "container" ]]; then

    if ! command -v podman &>/dev/null; then
        echo "FOUT: 'podman' niet gevonden. Installeer Podman eerst."
        exit 1
    fi

    echo "=== [1/4] Bestanden deployen naar $DEPLOY_DIR ==="
    mkdir -p "$DEPLOY_DIR"
    cp "$SCRIPT_DIR/proxy.py"         "$DEPLOY_DIR/proxy.py"
    cp "$SCRIPT_DIR/Dockerfile"       "$DEPLOY_DIR/Dockerfile"
    cp "$SCRIPT_DIR/requirements.txt" "$DEPLOY_DIR/requirements.txt"
    echo "proxy.py, Dockerfile, requirements.txt gekopieerd."
    _ensure_config

    echo ""
    echo "=== [2/4] Container image bouwen ==="
    podman build -t py-proxy:latest "$DEPLOY_DIR"

    echo ""
    echo "=== [3/4] Systemd service installeren ==="
    cp "$SCRIPT_DIR/proxy-container.service" "${SYSTEMD_DIR}/${SERVICE_NAME}.service"
    chmod 644 "${SYSTEMD_DIR}/${SERVICE_NAME}.service"
    systemctl daemon-reload

    echo ""
    echo "=== [4/4] Service activeren en (her)starten ==="
    systemctl enable "${SERVICE_NAME}.service"
    systemctl restart "${SERVICE_NAME}.service"

    echo ""
    echo "=== Status ==="
    systemctl status "${SERVICE_NAME}.service" --no-pager -l || true

    echo ""
    echo "Klaar. De proxy draait als Podman container, gestart door systemd als root."
    echo ""
    echo "Handige commando's:"
    echo "  systemctl status  ${SERVICE_NAME}     # status bekijken"
    echo "  journalctl -u ${SERVICE_NAME} -f       # logs volgen"
    echo "  systemctl reload  ${SERVICE_NAME}     # config herladen (SIGHUP)"
    echo "  systemctl restart ${SERVICE_NAME}     # herstarten"
    echo "  systemctl stop    ${SERVICE_NAME}     # stoppen"

fi

echo ""
echo "Admin UI: https://<host>:9443/"
