#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/common.sh"

need_cmd qemu-img
need_cmd curl
ensure_state_dirs

tmp="$FFSFS_VM_BASE_IMAGE.download"
if [ -f "$FFSFS_VM_BASE_IMAGE" ]; then
    echo "base image already exists: $FFSFS_VM_BASE_IMAGE"
    exit 0
fi

echo "downloading: $FFSFS_VM_IMAGE_URL"
curl -L --fail --output "$tmp" "$FFSFS_VM_IMAGE_URL"
qemu-img convert -O qcow2 "$tmp" "$FFSFS_VM_BASE_IMAGE"
rm -f "$tmp"
qemu-img resize "$FFSFS_VM_BASE_IMAGE" "${FFSFS_VM_BASE_SIZE:-12G}" >/dev/null
echo "created base image: $FFSFS_VM_BASE_IMAGE"
