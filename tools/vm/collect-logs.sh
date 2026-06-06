#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/common.sh"

run_id="${1:-}"
if [ -z "$run_id" ]; then
    echo "usage: $0 <run-id-or-log-dir>" >&2
    echo "available logs:" >&2
    find "$FFSFS_VM_LOG_DIR" -mindepth 1 -maxdepth 1 -type d -printf '  %f\n' 2>/dev/null | sort >&2 || true
    exit 1
fi

if [ -d "$run_id" ]; then
    src="$run_id"
else
    src="$FFSFS_VM_LOG_DIR/$run_id"
fi

if [ ! -d "$src" ]; then
    echo "log directory not found: $src" >&2
    exit 1
fi

archive="$FFSFS_VM_LOG_DIR/$(basename "$src").tar.gz"
tar -C "$(dirname "$src")" -czf "$archive" "$(basename "$src")"
echo "$archive"
