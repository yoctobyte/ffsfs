#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/common.sh"

need_cmd qemu-system-x86_64
need_cmd qemu-img
need_cmd cloud-localds
need_cmd ssh
need_cmd rsync
need_cmd curl
ensure_state_dirs
ensure_ssh_key

name_a="${FFSFS_VM_PEER_A_NAME:-ffsfs-vm-peer-a}"
name_b="${FFSFS_VM_PEER_B_NAME:-ffsfs-vm-peer-b}"
ssh_a="${FFSFS_VM_PEER_A_SSH_PORT:-2222}"
ssh_b="${FFSFS_VM_PEER_B_SSH_PORT:-2223}"
peer_guest_port="${FFSFS_VM_PEER_GUEST_PORT:-18765}"
peer_a_host_port="${FFSFS_VM_PEER_A_HOST_PORT:-28765}"
peer_b_host_port="${FFSFS_VM_PEER_B_HOST_PORT:-28766}"
realm="${FFSFS_VM_PEER_REALM:-vmpeer}"

if [ ! -f "$FFSFS_VM_BASE_IMAGE" ]; then
    echo "base image missing: $FFSFS_VM_BASE_IMAGE" >&2
    echo "run tools/vm/build-base-image.sh first" >&2
    exit 1
fi

run_id="two-peer-$(date +%Y%m%d-%H%M%S)"
run_dir="$FFSFS_VM_RUN_DIR/$run_id"
log_dir="$FFSFS_VM_LOG_DIR/$run_id"
mkdir -p "$run_dir" "$log_dir"

cpu_model="${FFSFS_VM_CPU_MODEL:-max}"
if [ -e /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    cpu_model="${FFSFS_VM_CPU_MODEL:-host}"
fi

boot_vm() {
    local name="$1"
    local ssh_port="$2"
    local peer_host_port="$3"
    local overlay="$run_dir/$name.qcow2"
    local seed="$run_dir/$name.seed.iso"
    local pidfile="$run_dir/$name.pid"

    qemu-img create -f qcow2 -F qcow2 -b "$FFSFS_VM_BASE_IMAGE" "$overlay" >/dev/null
    write_cloud_init_seed "$seed" "$name"

    qemu-system-x86_64 \
        -name "$name" \
        -machine accel=kvm:tcg \
        -cpu "$cpu_model" \
        -smp "$FFSFS_VM_CPUS" \
        -m "$FFSFS_VM_MEMORY" \
        -drive "file=$overlay,if=virtio,format=qcow2" \
        -drive "file=$seed,if=virtio,format=raw,readonly=on" \
        -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$ssh_port-:22,hostfwd=tcp:127.0.0.1:$peer_host_port-:$peer_guest_port" \
        -device virtio-net-pci,netdev=net0 \
        -nographic \
        -serial "file:$log_dir/$name.serial.log" \
        -monitor "unix:$run_dir/$name.monitor.sock,server,nowait" \
        >"$log_dir/$name.qemu.stdout.log" 2>"$log_dir/$name.qemu.stderr.log" &
    echo "$!" > "$pidfile"
}

cleanup() {
    for pidfile in "$run_dir"/*.pid; do
        [ -f "$pidfile" ] || continue
        pid="$(cat "$pidfile")"
        if kill -0 "$pid" >/dev/null 2>&1; then
            kill "$pid" >/dev/null 2>&1 || true
            wait "$pid" >/dev/null 2>&1 || true
        fi
    done
}
trap cleanup EXIT

collect_guest_debug() {
    local ssh_port="$1"
    local name="$2"
    {
        echo "== processes =="
        vm_ssh "$ssh_port" "ps -ef | grep -E 'ffsfs|start-peer|python3' | grep -v grep || true" || true
        echo "== sockets =="
        vm_ssh "$ssh_port" "ss -ltnp || true" || true
        echo "== peer log =="
        vm_ssh "$ssh_port" "cat /tmp/ffsfs-peer.log 2>/dev/null || true" || true
    } > "$log_dir/$name.debug.log" 2>&1
}

boot_vm "$name_a" "$ssh_a" "$peer_a_host_port"
boot_vm "$name_b" "$ssh_b" "$peer_b_host_port"

echo "waiting for SSH: $name_a on $ssh_a, $name_b on $ssh_b"
wait_for_ssh "$ssh_a"
wait_for_ssh "$ssh_b"
vm_ssh "$ssh_a" "command -v cloud-init >/dev/null 2>&1 && sudo cloud-init status --wait || true"
vm_ssh "$ssh_b" "command -v cloud-init >/dev/null 2>&1 && sudo cloud-init status --wait || true"

for port in "$ssh_a" "$ssh_b"; do
    vm_ssh "$port" "mkdir -p /home/$FFSFS_VM_USER/work/ffsfs"
    vm_rsync_repo "$port" "/home/$FFSFS_VM_USER/work/ffsfs"
done

start_peer_cmd='
set -euo pipefail
cd /home/'"$FFSFS_VM_USER"'/work/ffsfs
mkdir -p /tmp/ffsfs-peer-data/.ffsfs_data
cat > /tmp/start-peer.py <<PY
from types import SimpleNamespace
import time
import ffspeers

ffspeers.AUTO_DISCOVER = False
ffspeers.set_realm("'"$realm"'")
ffspeers.register_local_backend(SimpleNamespace(data_path="/tmp/ffsfs-peer-data/.ffsfs_data"))
ffspeers.start_local_peer_server('"$peer_guest_port"')
while True:
    time.sleep(60)
PY
nohup env PYTHONPATH=/home/'"$FFSFS_VM_USER"'/work/ffsfs python3 /tmp/start-peer.py > /tmp/ffsfs-peer.log 2>&1 &
'

vm_ssh "$ssh_a" "$start_peer_cmd"
vm_ssh "$ssh_b" "$start_peer_cmd"
sleep 2
collect_guest_debug "$ssh_a" "$name_a"
collect_guest_debug "$ssh_b" "$name_b"

echo "waiting for peer HTTP ports"
for port in "$peer_a_host_port" "$peer_b_host_port"; do
    deadline=$((SECONDS + 90))
    until curl -fsS "http://127.0.0.1:$port/healthz" >/dev/null 2>&1; do
        if [ "$SECONDS" -ge "$deadline" ]; then
            echo "timed out waiting for peer HTTP on host port $port" >&2
            collect_guest_debug "$ssh_a" "$name_a"
            collect_guest_debug "$ssh_b" "$name_b"
            exit 1
        fi
        sleep 2
    done
done

cross_check_a='
python3 - <<PY
import json
import urllib.request
data = json.load(urllib.request.urlopen("http://10.0.2.2:'"$peer_b_host_port"'/healthz", timeout=5))
assert data["realm"] == "'"$realm"'", data
print("peer-a reached peer-b", data)
PY
'
cross_check_b='
python3 - <<PY
import json
import urllib.request
data = json.load(urllib.request.urlopen("http://10.0.2.2:'"$peer_a_host_port"'/healthz", timeout=5))
assert data["realm"] == "'"$realm"'", data
print("peer-b reached peer-a", data)
PY
'

vm_ssh "$ssh_a" "$cross_check_a" | tee "$log_dir/$name_a.cross-check.log"
vm_ssh "$ssh_b" "$cross_check_b" | tee "$log_dir/$name_b.cross-check.log"

echo "two-peer reachability passed"
echo "logs: $log_dir"
