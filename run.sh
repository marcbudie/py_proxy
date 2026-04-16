#!/usr/bin/env bash
# run.sh — start de proxy direct met systeem-python3 (voor handmatig testen)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec /usr/bin/python3 "$SCRIPT_DIR/proxy.py" "$SCRIPT_DIR/config.json"
