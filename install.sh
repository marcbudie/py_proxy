#!/bin/bash
set -euo pipefail

CONTAINER_NAME="haproxy-sni"
IMAGE_NAME="haproxy-sni:latest"
CONFIG_DIR="$(cd "$(dirname "$0")" && pwd)"
QUADLET_DIR="/etc/containers/systemd"
SERVICE_NAME="haproxy-sni"

echo "==> Bouw container image (als root): ${IMAGE_NAME}"
sudo podman build -t "${IMAGE_NAME}" "${CONFIG_DIR}"

echo "==> Installeer Quadlet service-bestand"
sudo cp "${CONFIG_DIR}/haproxy-sni.container" "${QUADLET_DIR}/${SERVICE_NAME}.container"

echo "==> Herlaad systemd"
sudo systemctl daemon-reload

echo "==> Start/herstart service"
sudo systemctl restart "${SERVICE_NAME}.service"

echo "==> Status:"
sudo systemctl status "${SERVICE_NAME}.service" --no-pager
