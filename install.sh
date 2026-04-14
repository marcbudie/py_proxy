#!/usr/bin/env bash
# install.sh — bouw de container en installeer/herstart de systemd service
# Gebruik: sudo bash install.sh
# Opnieuw uitvoeren na elke nieuwe versie van proxy.py

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Dit script moet als root worden uitgevoerd."
    echo "Gebruik: sudo $0"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_NAME="py-proxy"
SYSTEMD_DIR="/etc/systemd/system"

echo "=== [1/4] Container image bouwen ==="
cd "$SCRIPT_DIR"
podman build -t localhost/py-proxy:latest -f Containerfile .

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
echo "  systemctl restart ${SERVICE_NAME}   # herstarten"
echo "  systemctl stop    ${SERVICE_NAME}   # stoppen"
echo ""
echo "Admin UI: https://<host>:9443/"
