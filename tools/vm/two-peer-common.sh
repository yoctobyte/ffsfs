#!/usr/bin/env bash
# Two-peer scenarios inside a SINGLE disposable VM.
#
# Both peer servers run on the same guest (different ports, different data
# dirs, different realm node names). This keeps the TCG boot cost to one VM;
# a multi-VM layout is reserved for future stress/config tests.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

need_two_peer_cmds() {
    need_cmd qemu-system-x86_64
    need_cmd qemu-img
    need_cmd cloud-localds
    need_cmd ssh
    need_cmd rsync
    need_cmd curl
}

two_peer_init() {
    need_two_peer_cmds
    ensure_state_dirs
    ensure_ssh_key

    name_a="${FFSFS_VM_PEER_A_NAME:-peer-a}"
    name_b="${FFSFS_VM_PEER_B_NAME:-peer-b}"
    vm_name="${FFSFS_VM_TWO_PEER_NAME:-ffsfs-vm-two-peer}"
    ssh_port="${FFSFS_VM_TWO_PEER_SSH_PORT:-2224}"
    peer_a_port="${FFSFS_VM_PEER_A_PORT:-18765}"
    peer_b_port="${FFSFS_VM_PEER_B_PORT:-18766}"
    peer_a_host_port="${FFSFS_VM_PEER_A_HOST_PORT:-28765}"
    peer_b_host_port="${FFSFS_VM_PEER_B_HOST_PORT:-28766}"
    realm="${FFSFS_VM_PEER_REALM:-vmpeer}"
    peer_a_data_base="${FFSFS_VM_PEER_A_DATA:-/tmp/ffsfs-peer-data}"
    peer_b_data_base="${FFSFS_VM_PEER_B_DATA:-/tmp/ffsfs-peer-data-b}"

    if [ ! -f "$FFSFS_VM_BASE_IMAGE" ]; then
        echo "base image missing: $FFSFS_VM_BASE_IMAGE" >&2
        echo "run tools/vm/build-base-image.sh first" >&2
        exit 1
    fi

    run_id="${FFSFS_VM_RUN_ID:-two-peer-$(date +%Y%m%d-%H%M%S)}"
    run_dir="$FFSFS_VM_RUN_DIR/$run_id"
    log_dir="$FFSFS_VM_LOG_DIR/$run_id"
    mkdir -p "$run_dir" "$log_dir"

    cpu_model="${FFSFS_VM_CPU_MODEL:-max}"
    if [ -e /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
        cpu_model="${FFSFS_VM_CPU_MODEL:-host}"
    fi
}

two_peer_boot_and_sync() {
    local overlay="$run_dir/$vm_name.qcow2"
    local seed="$run_dir/$vm_name.seed.iso"
    local pidfile="$run_dir/$vm_name.pid"

    qemu-img create -f qcow2 -F qcow2 -b "$FFSFS_VM_BASE_IMAGE" "$overlay" >/dev/null
    write_cloud_init_seed "$seed" "$vm_name"

    # Forward SSH plus both peer ports. Peer ports are forwarded so an
    # operator can curl them from the host while debugging; scenarios
    # themselves reach the peers over the guest loopback.
    qemu-system-x86_64 \
        -name "$vm_name" \
        -machine accel=kvm:tcg \
        -cpu "$cpu_model" \
        -smp "$FFSFS_VM_CPUS" \
        -m "$FFSFS_VM_MEMORY" \
        -drive "file=$overlay,if=virtio,format=qcow2" \
        -drive "file=$seed,if=virtio,format=raw,readonly=on" \
        -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$ssh_port-:22,hostfwd=tcp:127.0.0.1:$peer_a_host_port-:$peer_a_port,hostfwd=tcp:127.0.0.1:$peer_b_host_port-:$peer_b_port" \
        -device virtio-net-pci,netdev=net0 \
        -nographic \
        -serial "file:$log_dir/$vm_name.serial.log" \
        -monitor "unix:$run_dir/$vm_name.monitor.sock,server,nowait" \
        >"$log_dir/$vm_name.qemu.stdout.log" 2>"$log_dir/$vm_name.qemu.stderr.log" &
    echo "$!" > "$pidfile"

    echo "waiting for $vm_name SSH on 127.0.0.1:$ssh_port"
    wait_for_ssh "$ssh_port"
    vm_ssh "$ssh_port" "command -v cloud-init >/dev/null 2>&1 && sudo cloud-init status --wait || true"

    vm_ssh "$ssh_port" "mkdir -p /home/$FFSFS_VM_USER/work/ffsfs"
    vm_rsync_repo "$ssh_port" "/home/$FFSFS_VM_USER/work/ffsfs"
}

two_peer_start_servers() {
    local data_a="$peer_a_data_base/.ffsfs_data"
    local data_b="$peer_b_data_base/.ffsfs_data"

    local start_peer_a='
set -euo pipefail
cd /home/'"$FFSFS_VM_USER"'/work/ffsfs
mkdir -p '"$data_a"'
cat > /tmp/start-peer-a.py <<PY
from types import SimpleNamespace
import time
import ffspeers

ffspeers.AUTO_DISCOVER = False
ffspeers.set_realm("'"$realm"'")
ffspeers.register_local_backend(SimpleNamespace(data_path="'"$data_a"'"))
ffspeers.start_local_peer_server('"$peer_a_port"')
while True:
    time.sleep(60)
PY
nohup env PYTHONPATH=/home/'"$FFSFS_VM_USER"'/work/ffsfs \
    python3 /tmp/start-peer-a.py > /tmp/ffsfs-peer-a.log 2>&1 &
'

    local start_peer_b='
set -euo pipefail
cd /home/'"$FFSFS_VM_USER"'/work/ffsfs
mkdir -p '"$data_b"'
cat > /tmp/start-peer-b.py <<PY
from types import SimpleNamespace
import time
import ffspeers

ffspeers.AUTO_DISCOVER = False
ffspeers.set_realm("'"$realm"'")
ffspeers.register_local_backend(SimpleNamespace(data_path="'"$data_b"'"))
ffspeers.start_local_peer_server('"$peer_b_port"')
while True:
    time.sleep(60)
PY
nohup env PYTHONPATH=/home/'"$FFSFS_VM_USER"'/work/ffsfs \
    python3 /tmp/start-peer-b.py > /tmp/ffsfs-peer-b.log 2>&1 &
'

    vm_ssh "$ssh_port" "$start_peer_a"
    vm_ssh "$ssh_port" "$start_peer_b"
    sleep 2
}

two_peer_wait_for_http() {
    echo "waiting for peer HTTP ports (in-guest loopback)"
    local check='
for port in '"$peer_a_port"' '"$peer_b_port"'; do
    deadline=$((SECONDS + 90))
    until curl -fsS "http://127.0.0.1:$port/healthz" >/dev/null 2>&1; do
        if [ "$SECONDS" -ge "$deadline" ]; then
            echo "timed out waiting for peer HTTP on guest port $port" >&2
            exit 1
        fi
        sleep 2
    done
    echo "peer on :$port healthy"
done
'
    vm_ssh "$ssh_port" "$check"
}

two_peer_cleanup() {
    for pidfile in "$run_dir"/*.pid; do
        [ -f "$pidfile" ] || continue
        pid="$(cat "$pidfile")"
        if kill -0 "$pid" >/dev/null 2>&1; then
            kill "$pid" >/dev/null 2>&1 || true
            wait "$pid" >/dev/null 2>&1 || true
        fi
    done
}

two_peer_run_a() {
    vm_ssh "$ssh_port" "$@"
}

two_peer_run_b() {
    vm_ssh "$ssh_port" "$@"
}

two_peer_healthz_cross_check() {
    local cross_check_a='
python3 - <<PY
import json
import urllib.request
data = json.load(urllib.request.urlopen("http://127.0.0.1:'"$peer_b_port"'/healthz", timeout=5))
assert data["realm"] == "'"$realm"'", data
print("peer-a reached peer-b", data)
PY
'
    local cross_check_b='
python3 - <<PY
import json
import urllib.request
data = json.load(urllib.request.urlopen("http://127.0.0.1:'"$peer_a_port"'/healthz", timeout=5))
assert data["realm"] == "'"$realm"'", data
print("peer-b reached peer-a", data)
PY
'

    two_peer_run_a "$cross_check_a" | tee "$log_dir/$name_a.cross-check.log"
    two_peer_run_b "$cross_check_b" | tee "$log_dir/$name_b.cross-check.log"
}
