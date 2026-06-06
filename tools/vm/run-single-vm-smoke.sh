#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/common.sh"

guest_script='
set -euo pipefail
cd /home/'"$FFSFS_VM_USER"'/work/ffsfs
python3 -m py_compile *.py
pytest -q
mkdir -p /tmp/ffsfs-mount /tmp/ffsfs-storage
python3 ffsfs.py --base /tmp/ffsfs-storage --realm vmtest --port 18765 --bg /tmp/ffsfs-mount > /tmp/ffsfs-peer.log 2>&1 &
pid=$!
cleanup() {
    fusermount3 -u /tmp/ffsfs-mount >/dev/null 2>&1 || fusermount -u /tmp/ffsfs-mount >/dev/null 2>&1 || true
    kill "$pid" >/dev/null 2>&1 || true
}
trap cleanup EXIT
for _ in $(seq 1 30); do
    if mountpoint -q /tmp/ffsfs-mount; then
        break
    fi
    sleep 1
done
mountpoint -q /tmp/ffsfs-mount
printf hello > /tmp/ffsfs-mount/hello.txt
sync /tmp/ffsfs-mount/hello.txt || true
test "$(cat /tmp/ffsfs-mount/hello.txt)" = hello
rm /tmp/ffsfs-mount/hello.txt
sleep 1
find /tmp/ffsfs-storage -maxdepth 5 -type f -print
'

"$VM_DIR/run-one-vm.sh" ffsfs-vm-single "$guest_script"
