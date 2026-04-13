#!/usr/bin/env bash
# backup.sh — Maakt een backup van de certtool directory naar Google Drive via rclone.
#
# Gebruik:
#   ./backup.sh
#
# Vereisten:
#   rclone geconfigureerd met een remote genaamd 'gdrive'

REMOTE="google:backup/py_proxy"
SOURCE="$(cd "$(dirname "$0")" && pwd)"
LOG="$SOURCE/backup.log"

{
    echo "Backup gestart op $(date '+%Y-%m-%d %H:%M:%S')"
    echo "  $SOURCE → $REMOTE"

    rclone sync "$SOURCE" "$REMOTE" \
        --exclude ".git/**" \
        --exclude "__pycache__/**" \
        --exclude "**/*.pyc" \
        --exclude "pyvenv.cfg" \
        --exclude "bin/**" \
        --exclude "include/**" \
        --exclude "lib/**" \
        --exclude "lib64" \
        --exclude "lib64/**" \
        --exclude "build/**" \
        --exclude "dist/**" \
        --exclude ".pytest_cache/**" \
        --exclude "backup.log" \
        --exclude "*.pem" \
        --exclude "*.crt" \
        --exclude "*.cer" \
        --exclude "*.key" \
        --exclude "*.der" \
        --exclude "*.p12" \
        --exclude "*.pfx" \
        --exclude "*.p7b" \
        --exclude "*.jks" \
        --exclude "*.zip" \
        --fast-list \
        --progress

    if [ $? -eq 0 ]; then
        echo "Backup geslaagd op $(date '+%Y-%m-%d %H:%M:%S')"
    else
        echo "Backup mislukt!"
        exit 1
    fi
} 2>&1 | tee "$LOG"
