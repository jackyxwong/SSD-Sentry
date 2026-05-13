#!/bin/bash
set -euo pipefail

SERVICE_LABEL="com.ssdsentry.daemon"
SERVICE_TARGET="system/$SERVICE_LABEL"
PLIST="/Library/LaunchDaemons/${SERVICE_LABEL}.plist"
INSTALL_DIR="/usr/local/ssd-sentry"
LOG_DIR="/var/log/ssd-sentry"
STATE_DIR="/var/db/ssd-sentry"
RUN_DIR="/var/run/ssd-sentry"
CLI_LINK="/usr/local/bin/ssd-sentry"
UNINSTALL_LINK="/usr/local/bin/ssd-sentry-uninstall"

if [ "$(id -u)" -ne 0 ]; then
  echo "Please run with sudo."
  exit 1
fi

if [ "${KEEP_CONFIG:-0}" = "1" ] && [ -f "$INSTALL_DIR/config.json" ]; then
  cp "$INSTALL_DIR/config.json" "/tmp/ssd-sentry-config.json"
  echo "Backed up config to /tmp/ssd-sentry-config.json"
fi

if /bin/launchctl print "$SERVICE_TARGET" >/dev/null 2>&1; then
  /bin/launchctl bootout "$SERVICE_TARGET" 2>/dev/null || true
  /bin/launchctl disable "$SERVICE_TARGET" 2>/dev/null || true
fi

if [ -f "$PLIST" ]; then
  /bin/launchctl unload "$PLIST" 2>/dev/null || true
  rm -f "$PLIST"
fi

rm -f "$CLI_LINK" "$UNINSTALL_LINK"
rm -rf "$INSTALL_DIR" "$LOG_DIR" "$STATE_DIR" "$RUN_DIR"

echo "SSD Sentry uninstall complete."
