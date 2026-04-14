#!/usr/bin/env bash
# run.sh — start de proxy vanuit de venv (voor handmatig testen)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/venv/bin/python3" "$SCRIPT_DIR/proxy.py" "$SCRIPT_DIR/config.json"
