#!/usr/bin/env bash
set -euo pipefail

VM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$VM_DIR/../.." && pwd)"

FFSFS_VM_STATE_DIR="${FFSFS_VM_STATE_DIR:-$REPO_ROOT/.vm}"
FFSFS_VM_IMAGE_DIR="${FFSFS_VM_IMAGE_DIR:-$FFSFS_VM_STATE_DIR/images}"
FFSFS_VM_RUN_DIR="${FFSFS_VM_RUN_DIR:-$FFSFS_VM_STATE_DIR/runs}"
FFSFS_VM_LOG_DIR="${FFSFS_VM_LOG_DIR:-$FFSFS_VM_STATE_DIR/logs}"
FFSFS_VM_SSH_KEY="${FFSFS_VM_SSH_KEY:-$FFSFS_VM_STATE_DIR/ssh/id_ed25519}"
FFSFS_VM_USER="${FFSFS_VM_USER:-ubuntu}"
FFSFS_VM_BASE_IMAGE="${FFSFS_VM_BASE_IMAGE:-$FFSFS_VM_IMAGE_DIR/ubuntu-24.04-server-cloudimg-amd64.qcow2}"
FFSFS_VM_IMAGE_URL="${FFSFS_VM_IMAGE_URL:-https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img}"
FFSFS_VM_CPUS="${FFSFS_VM_CPUS:-2}"
FFSFS_VM_MEMORY="${FFSFS_VM_MEMORY:-2048}"
FFSFS_VM_SSH_WAIT_SECS="${FFSFS_VM_SSH_WAIT_SECS:-180}"

need_cmd() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "missing required command: $cmd" >&2
        exit 1
    fi
}

ensure_state_dirs() {
    mkdir -p "$FFSFS_VM_IMAGE_DIR" "$FFSFS_VM_RUN_DIR" "$FFSFS_VM_LOG_DIR" "$(dirname "$FFSFS_VM_SSH_KEY")"
}

ensure_ssh_key() {
    ensure_state_dirs
    if [ ! -f "$FFSFS_VM_SSH_KEY" ]; then
        ssh-keygen -t ed25519 -N "" -f "$FFSFS_VM_SSH_KEY" -C "ffsfs-vm-test" >/dev/null
    fi
}

ssh_opts() {
    printf '%s\n' \
        -i "$FFSFS_VM_SSH_KEY" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        -o ConnectTimeout=5
}

wait_for_ssh() {
    local port="$1"
    local deadline=$((SECONDS + FFSFS_VM_SSH_WAIT_SECS))
    local opts
    mapfile -t opts < <(ssh_opts)
    until ssh "${opts[@]}" -p "$port" "$FFSFS_VM_USER@127.0.0.1" "true" >/dev/null 2>&1; do
        if [ "$SECONDS" -ge "$deadline" ]; then
            echo "timed out waiting for SSH on port $port" >&2
            return 1
        fi
        sleep 2
    done
}

vm_ssh() {
    local port="$1"
    shift
    local opts
    mapfile -t opts < <(ssh_opts)
    ssh "${opts[@]}" -p "$port" "$FFSFS_VM_USER@127.0.0.1" "$@"
}

vm_rsync_repo() {
    local port="$1"
    local dest="$2"
    local opts
    mapfile -t opts < <(ssh_opts)
    rsync -az --delete \
        --exclude .git \
        --exclude .storage \
        --exclude .vm \
        --exclude __pycache__ \
        --exclude .pytest_cache \
        -e "ssh ${opts[*]} -p $port" \
        "$REPO_ROOT/" "$FFSFS_VM_USER@127.0.0.1:$dest/"
}

write_cloud_init_seed() {
    local seed_path="$1"
    local hostname="$2"
    local pubkey
    pubkey="$(cat "$FFSFS_VM_SSH_KEY.pub")"
    local user_data meta_data
    user_data="$(mktemp)"
    meta_data="$(mktemp)"
    cat > "$user_data" <<EOF
#cloud-config
hostname: $hostname
users:
  - default
  - name: $FFSFS_VM_USER
    groups: sudo
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - $pubkey
package_update: true
packages:
  - git
  - python3
  - python3-pytest
  - python3-flask
  - python3-requests
  - python3-fusepy
  - fuse3
runcmd:
  - [ sh, -c, "apt-get install -y libfuse2t64 || apt-get install -y libfuse2" ]
  - [ sh, -c, "mkdir -p /home/$FFSFS_VM_USER/work && chown -R $FFSFS_VM_USER:$FFSFS_VM_USER /home/$FFSFS_VM_USER/work" ]
EOF
    cat > "$meta_data" <<EOF
instance-id: $hostname-$(date +%s)
local-hostname: $hostname
EOF
    cloud-localds "$seed_path" "$user_data" "$meta_data"
    rm -f "$user_data" "$meta_data"
}
