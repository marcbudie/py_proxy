#!/usr/bin/env bash
# backup.sh — Maakt een backup van de certtool directory naar Google Drive via rclone.
#
# Gebruik:
#   ./backup.sh
#
# Vereisten:
#   rclone geconfigureerd met een remote genaamd 'gdrive'

REMOTES=("google:backup/py_proxy" "onedrive:backup/py_proxy")
SOURCE="$(cd "$(dirname "$0")" && pwd)"
RCLONE_CONFIG="$(cd "$(dirname "$0")/../rclone-config" && pwd)/rclone.conf"
LOG="$SOURCE/backup.log"

{
    echo "Backup gestart op $(date '+%Y-%m-%d %H:%M:%S')"
    ERRORS=0
    for REMOTE in "${REMOTES[@]}"; do
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
            --config "$RCLONE_CONFIG" \
            --fast-list \
            --progress
        if [ $? -eq 0 ]; then
            echo "  Geslaagd: $REMOTE"
        else
            echo "  Mislukt: $REMOTE"
            ERRORS=$((ERRORS + 1))
        fi
    done

    if [ $ERRORS -eq 0 ]; then
        echo "Alle backups geslaagd op $(date '+%Y-%m-%d %H:%M:%S')"
    else
        echo "$ERRORS backup(s) mislukt op $(date '+%Y-%m-%d %H:%M:%S')"
        exit 1
    fi
} 2>&1 | tee "$LOG"
