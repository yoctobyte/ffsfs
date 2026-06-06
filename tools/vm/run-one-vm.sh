#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/common.sh"

need_cmd qemu-system-x86_64
need_cmd qemu-img
need_cmd cloud-localds
need_cmd ssh
need_cmd rsync
ensure_state_dirs
ensure_ssh_key

name="${1:-ffsfs-vm-single}"
shift || true
guest_cmd="${*:-cd /home/$FFSFS_VM_USER/work/ffsfs && python3 -m py_compile *.py && pytest -q}"

if [ ! -f "$FFSFS_VM_BASE_IMAGE" ]; then
    echo "base image missing: $FFSFS_VM_BASE_IMAGE" >&2
    echo "run tools/vm/build-base-image.sh first" >&2
    exit 1
fi

run_id="$name-$(date +%Y%m%d-%H%M%S)"
run_dir="$FFSFS_VM_RUN_DIR/$run_id"
log_dir="$FFSFS_VM_LOG_DIR/$run_id"
mkdir -p "$run_dir" "$log_dir"

overlay="$run_dir/disk.qcow2"
seed="$run_dir/seed.iso"
pidfile="$run_dir/qemu.pid"
ssh_port="${FFSFS_VM_SSH_PORT:-2222}"
cpu_model="${FFSFS_VM_CPU_MODEL:-max}"
if [ -e /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    cpu_model="${FFSFS_VM_CPU_MODEL:-host}"
fi

qemu-img create -f qcow2 -F qcow2 -b "$FFSFS_VM_BASE_IMAGE" "$overlay" >/dev/null
write_cloud_init_seed "$seed" "$name"

cleanup() {
    if [ -f "$pidfile" ]; then
        pid="$(cat "$pidfile")"
        if kill -0 "$pid" >/dev/null 2>&1; then
            kill "$pid" >/dev/null 2>&1 || true
            wait "$pid" >/dev/null 2>&1 || true
        fi
    fi
}
trap cleanup EXIT

qemu-system-x86_64 \
    -name "$name" \
    -machine accel=kvm:tcg \
    -cpu "$cpu_model" \
    -smp "$FFSFS_VM_CPUS" \
    -m "$FFSFS_VM_MEMORY" \
    -drive "file=$overlay,if=virtio,format=qcow2" \
    -drive "file=$seed,if=virtio,format=raw,readonly=on" \
    -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$ssh_port-:22" \
    -device virtio-net-pci,netdev=net0 \
    -nographic \
    -serial "file:$log_dir/serial.log" \
    -monitor "unix:$run_dir/monitor.sock,server,nowait" \
    >"$log_dir/qemu.stdout.log" 2>"$log_dir/qemu.stderr.log" &
echo "$!" > "$pidfile"

echo "waiting for $name SSH on 127.0.0.1:$ssh_port"
wait_for_ssh "$ssh_port"

vm_ssh "$ssh_port" "mkdir -p /home/$FFSFS_VM_USER/work/ffsfs"
vm_rsync_repo "$ssh_port" "/home/$FFSFS_VM_USER/work/ffsfs"

echo "running guest command: $guest_cmd"
vm_ssh "$ssh_port" "$guest_cmd" | tee "$log_dir/guest-command.log"

echo "logs: $log_dir"
