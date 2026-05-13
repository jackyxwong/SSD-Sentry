#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
STATE_FILE="$(mktemp /tmp/ssd-sentry-state.XXXXXX.json)"
trap 'rm -f "$STATE_FILE"' EXIT

python3 "$SCRIPT_DIR/ssd_sentry_monitor.py" \
  --once \
  --dry-run \
  --config "$SCRIPT_DIR/config.json" \
  --state "$STATE_FILE"
