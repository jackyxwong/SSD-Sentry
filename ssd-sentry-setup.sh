#!/bin/bash
set -euo pipefail

APP_NAME="SSD Sentry"
SERVICE_LABEL="com.ssdsentry.daemon"
SERVICE_TARGET="system/$SERVICE_LABEL"
INSTALL_DIR="/usr/local/ssd-sentry"
BIN_DIR="/usr/local/bin"
LOG_DIR="/var/log/ssd-sentry"
STATE_DIR="/var/db/ssd-sentry"
RUN_DIR="/var/run/ssd-sentry"
PLIST_DEST="/Library/LaunchDaemons/${SERVICE_LABEL}.plist"
CLI_LINK="$BIN_DIR/ssd-sentry"
UNINSTALL_LINK="$BIN_DIR/ssd-sentry-uninstall"
METADATA_DEST="$INSTALL_DIR/install-metadata.json"

resolve_script_dir() {
  local source_path="$1"
  while [ -L "$source_path" ]; do
    local source_dir
    source_dir="$(cd "$(dirname "$source_path")" && pwd)"
    source_path="$(readlink "$source_path")"
    if [[ "$source_path" != /* ]]; then
      source_path="$source_dir/$source_path"
    fi
  done
  cd "$(dirname "$source_path")" && pwd
}

find_preferred_python() {
  local setup_dir="$1"
  local detected_prefix=""
  local candidate=""

  case "$setup_dir" in
    */Cellar/ssd-sentry/*/libexec)
      detected_prefix="$(cd "$setup_dir/../../../.." && pwd)"
      ;;
  esac

  if [ -n "$detected_prefix" ]; then
    for candidate in \
      "$detected_prefix/opt/python@3.11/bin/python3.11" \
      "$detected_prefix/opt/python@3.11/bin/python3"
    do
      if [ -x "$candidate" ]; then
        echo "$candidate"
        return 0
      fi
    done
  fi

  for candidate in \
    /opt/homebrew/opt/python@3.11/bin/python3.11 \
    /opt/homebrew/opt/python@3.11/bin/python3 \
    /usr/local/opt/python@3.11/bin/python3.11 \
    /usr/local/opt/python@3.11/bin/python3
  do
    if [ -x "$candidate" ]; then
      echo "$candidate"
      return 0
    fi
  done

  command -v python3 2>/dev/null || true
}

SCRIPT_DIR="$(resolve_script_dir "${BASH_SOURCE[0]}")"
SCRIPT_SRC="$SCRIPT_DIR/ssd_sentry_monitor.py"
CONFIG_SRC="$SCRIPT_DIR/config.json"
PLIST_SRC="$SCRIPT_DIR/com.ssdsentry.daemon.plist"
CLI_SRC="$SCRIPT_DIR/ssd-sentry"
UNINSTALL_SRC="$SCRIPT_DIR/ssd-sentry-uninstall.sh"

if [ "$(id -u)" -ne 0 ]; then
  echo "Please run with sudo."
  exit 1
fi

PYTHON_BIN="$(find_preferred_python "$SCRIPT_DIR")"
if [ -z "$PYTHON_BIN" ]; then
  echo "python3 not found on PATH."
  exit 1
fi

stop_service_if_present() {
  /bin/launchctl bootout "$SERVICE_TARGET" 2>/dev/null || true
  /bin/launchctl bootout system "$PLIST_DEST" 2>/dev/null || true

  if [ -f "$PLIST_DEST" ]; then
    rm -f "$PLIST_DEST"
  fi
}

mkdir -p "$INSTALL_DIR" "$LOG_DIR" "$STATE_DIR" "$RUN_DIR" "$BIN_DIR"
chmod 755 "$LOG_DIR" "$STATE_DIR" "$RUN_DIR"

if [ ! -f "$INSTALL_DIR/config.json" ]; then
  cp "$CONFIG_SRC" "$INSTALL_DIR/config.json"
else
  echo "Config exists at $INSTALL_DIR/config.json, leaving it unchanged."
fi
if [ -f "$STATE_DIR/state.json" ]; then
  chmod 644 "$STATE_DIR/state.json" || true
fi

cp "$SCRIPT_SRC" "$INSTALL_DIR/ssd_sentry_monitor.py"
cp "$CLI_SRC" "$INSTALL_DIR/ssd-sentry"
cp "$UNINSTALL_SRC" "$INSTALL_DIR/ssd-sentry-uninstall"
chmod 755 "$INSTALL_DIR/ssd_sentry_monitor.py" "$INSTALL_DIR/ssd-sentry" "$INSTALL_DIR/ssd-sentry-uninstall"
chmod 644 "$INSTALL_DIR/config.json" || true
chown -R root:wheel "$INSTALL_DIR" "$LOG_DIR" "$STATE_DIR" "$RUN_DIR"
ln -sf "$INSTALL_DIR/ssd-sentry" "$CLI_LINK"
ln -sf "$INSTALL_DIR/ssd-sentry-uninstall" "$UNINSTALL_LINK"

stop_service_if_present

sed "s#__PYTHON3__#$PYTHON_BIN#g" "$PLIST_SRC" > "$PLIST_DEST"
chmod 644 "$PLIST_DEST"
chown root:wheel "$PLIST_DEST"
/bin/launchctl enable "$SERVICE_TARGET" 2>/dev/null || true

if [ "${SKIP_AUTHRESTART:-0}" != "1" ]; then
  FV_STATUS=$(/usr/bin/fdesetup status 2>&1)
  if echo "$FV_STATUS" | /usr/bin/grep -q "FileVault is Off"; then
    echo "FileVault is off; authrestart is not available."
  elif echo "$FV_STATUS" | /usr/bin/grep -q "FileVault is On"; then
    echo "FileVault is already on; authrestart is available."
  else
    /usr/bin/fdesetup enable -authrestart 2>/dev/null || echo "Note: authrestart setup skipped (may already be enabled)."
  fi
fi

BOOTSTRAP_ERR="$(mktemp /tmp/ssd-sentry-bootstrap.XXXXXX)"
trap 'rm -f "$BOOTSTRAP_ERR"' EXIT
if /bin/launchctl bootstrap system "$PLIST_DEST" 2>"$BOOTSTRAP_ERR"; then
  /bin/launchctl enable "$SERVICE_TARGET"
  /bin/launchctl kickstart -k "$SERVICE_TARGET"
else
  if /bin/launchctl load -w "$PLIST_DEST"; then
    echo "launchctl bootstrap did not succeed; used load fallback instead."
  else
    cat "$BOOTSTRAP_ERR" >&2
    exit 1
  fi
fi

INSTALL_TIME="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
SCRIPT_SHA="$(shasum -a 256 "$INSTALL_DIR/ssd_sentry_monitor.py" | awk '{print $1}')"
CONFIG_SHA="$(shasum -a 256 "$INSTALL_DIR/config.json" | awk '{print $1}')"
CLI_SHA="$(shasum -a 256 "$INSTALL_DIR/ssd-sentry" | awk '{print $1}')"
VERSION="$(python3 "$INSTALL_DIR/ssd_sentry_monitor.py" --version)"
export SSDP_VERSION="$VERSION"
export SSDP_INSTALL_TIME="$INSTALL_TIME"
export SSDP_SOURCE_DIR="$SCRIPT_DIR"
export SSDP_INSTALL_DIR="$INSTALL_DIR"
export SSDP_SCRIPT_SHA="$SCRIPT_SHA"
export SSDP_CONFIG_SHA="$CONFIG_SHA"
export SSDP_CLI_SHA="$CLI_SHA"
export SSDP_METADATA_DEST="$METADATA_DEST"
python3 - <<'PY'
import json
import os

data = {
    "version": os.environ["SSDP_VERSION"],
    "installed_at_utc": os.environ["SSDP_INSTALL_TIME"],
    "source_dir": os.environ["SSDP_SOURCE_DIR"],
    "script_path": os.path.join(os.environ["SSDP_INSTALL_DIR"], "ssd_sentry_monitor.py"),
    "script_sha256": os.environ["SSDP_SCRIPT_SHA"],
    "config_path": os.path.join(os.environ["SSDP_INSTALL_DIR"], "config.json"),
    "config_sha256": os.environ["SSDP_CONFIG_SHA"],
    "cli_path": os.path.join(os.environ["SSDP_INSTALL_DIR"], "ssd-sentry"),
    "cli_sha256": os.environ["SSDP_CLI_SHA"],
}
with open(os.environ["SSDP_METADATA_DEST"], "w", encoding="utf-8") as handle:
    json.dump(data, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY

echo "${APP_NAME} install complete."
echo "CLI: $CLI_LINK"
echo "Logs: $LOG_DIR"
