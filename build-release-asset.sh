#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VERSION="${1:-$(python3 "$SCRIPT_DIR/ssd_sentry_monitor.py" --version)}"
OUT_DIR="${2:-$SCRIPT_DIR/dist}"
ASSET_BASENAME="ssd-sentry-v${VERSION}"
ASSET_PATH="$OUT_DIR/${ASSET_BASENAME}.tar.gz"
STAGE_DIR="$(mktemp -d)"
ROOT_DIR="$STAGE_DIR/$ASSET_BASENAME"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}"

FILES=(
  "ssd_sentry_monitor.py"
  "config.json"
  "ssd-sentry"
  "ssd-sentry-setup.sh"
  "ssd-sentry-uninstall.sh"
  "com.ssdsentry.daemon.plist"
  "ssd-sentry-dry-run.sh"
  "README.md"
  "requirements.txt"
  "LICENSE"
  "NOTICE"
)

cleanup() {
  rm -rf "$STAGE_DIR"
}
trap cleanup EXIT

mkdir -p "$ROOT_DIR" "$OUT_DIR"

for file in "${FILES[@]}"; do
  cp "$SCRIPT_DIR/$file" "$ROOT_DIR/$file"
done

chmod 755 \
  "$ROOT_DIR/ssd_sentry_monitor.py" \
  "$ROOT_DIR/ssd-sentry" \
  "$ROOT_DIR/ssd-sentry-setup.sh" \
  "$ROOT_DIR/ssd-sentry-uninstall.sh" \
  "$ROOT_DIR/ssd-sentry-dry-run.sh"

MANIFEST="$(printf '%s\n' "${FILES[@]}")"
export ASSET_PATH ASSET_BASENAME ROOT_DIR SOURCE_DATE_EPOCH MANIFEST

python3 - <<'PY'
import gzip
import os
import tarfile

asset_path = os.environ["ASSET_PATH"]
asset_basename = os.environ["ASSET_BASENAME"]
root_dir = os.environ["ROOT_DIR"]
source_date_epoch = int(os.environ["SOURCE_DATE_EPOCH"])
manifest = [line for line in os.environ["MANIFEST"].splitlines() if line]


def apply_common(info: tarfile.TarInfo, mode: int) -> tarfile.TarInfo:
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    info.mtime = source_date_epoch
    info.mode = mode
    return info


with open(asset_path, "wb") as raw_handle:
    with gzip.GzipFile(filename="", mode="wb", fileobj=raw_handle, mtime=source_date_epoch) as gzip_handle:
        with tarfile.open(fileobj=gzip_handle, mode="w", format=tarfile.USTAR_FORMAT) as tar_handle:
            root_info = tarfile.TarInfo(f"{asset_basename}/")
            root_info.type = tarfile.DIRTYPE
            tar_handle.addfile(apply_common(root_info, 0o755))

            for relative_path in manifest:
                absolute_path = os.path.join(root_dir, relative_path)
                archive_path = f"{asset_basename}/{relative_path}"
                stat_result = os.stat(absolute_path)

                file_info = tarfile.TarInfo(archive_path)
                file_info.size = stat_result.st_size
                file_mode = 0o755 if stat_result.st_mode & 0o111 else 0o644
                with open(absolute_path, "rb") as file_handle:
                    tar_handle.addfile(
                        apply_common(file_info, file_mode),
                        file_handle,
                    )
PY

SHA256="$(shasum -a 256 "$ASSET_PATH" | awk '{print $1}')"

echo "Asset: $ASSET_PATH"
echo "SHA256: $SHA256"
