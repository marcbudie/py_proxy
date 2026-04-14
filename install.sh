#!/usr/bin/env bash
# install.sh — maak venv aan, installeer systemd service en (her)start
# Gebruik: sudo bash install.sh

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Dit script moet als root worden uitgevoerd."
    echo "Gebruik: sudo $0"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_NAME="py-proxy"
SYSTEMD_DIR="/etc/systemd/system"
VENV_DIR="$SCRIPT_DIR/venv"
OWNER="admin"

echo "=== [1/4] Venv aanmaken en dependencies installeren ==="
python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --quiet --upgrade pip
if [[ -f "$SCRIPT_DIR/requirements.txt" ]]; then
    "$VENV_DIR/bin/pip" install --quiet -r "$SCRIPT_DIR/requirements.txt"
fi
chown -R "$OWNER:$OWNER" "$VENV_DIR"
chmod +x "$SCRIPT_DIR/run.sh"
echo "Venv klaar: $VENV_DIR"

echo ""
echo "=== [2/4] Systemd service installeren ==="
cp "$SCRIPT_DIR/proxy.service" "${SYSTEMD_DIR}/${SERVICE_NAME}.service"
chmod 644 "${SYSTEMD_DIR}/${SERVICE_NAME}.service"
systemctl daemon-reload

echo ""
echo "=== [3/4] Service activeren en (her)starten ==="
systemctl enable "${SERVICE_NAME}.service"
systemctl restart "${SERVICE_NAME}.service"

echo ""
echo "=== [4/4] Status ==="
systemctl status "${SERVICE_NAME}.service" --no-pager -l || true

echo ""
echo "Klaar. De proxy draait nu als systemd service '${SERVICE_NAME}'."
echo ""
echo "Handige commando's:"
echo "  systemctl status  ${SERVICE_NAME}   # status bekijken"
echo "  journalctl -u ${SERVICE_NAME} -f     # logs volgen"
echo "  systemctl reload  ${SERVICE_NAME}   # config herladen (SIGHUP)"
echo "  systemctl restart ${SERVICE_NAME}   # herstarten na nieuwe proxy.py"
echo "  systemctl stop    ${SERVICE_NAME}   # stoppen"
echo ""
echo "Admin UI: https://<host>:9443/"
