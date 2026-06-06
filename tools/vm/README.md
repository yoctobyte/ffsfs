# FFSFS VM Test Harness

Host-side scripts for disposable QEMU VM tests. Generated images, overlays,
seeds, and logs live under `.vm/` by default and are ignored by git.

## Host Dependencies

```bash
sudo apt install qemu-system-x86 qemu-utils cloud-image-utils curl rsync openssh-client
```

## Build Base Image

```bash
tools/vm/build-base-image.sh
```

Defaults:

- Image URL: Ubuntu 24.04 noble cloud image
- Base image: `.vm/images/ubuntu-24.04-server-cloudimg-amd64.qcow2`
- Size: `12G`

Override with environment variables:

```bash
FFSFS_VM_IMAGE_URL=https://example/image.qcow2 tools/vm/build-base-image.sh
FFSFS_VM_BASE_IMAGE=/path/base.qcow2 tools/vm/run-one-vm.sh
```

## Run Tests In One VM

```bash
tools/vm/run-one-vm.sh
```

This boots a disposable overlay, syncs the repository into the guest, and runs:

```bash
python3 -m py_compile *.py && pytest -q
```

Run a custom guest command:

```bash
tools/vm/run-one-vm.sh ffsfs-vm-single 'cd /home/ubuntu/work/ffsfs && pytest -q'
```

## Single-VM FUSE Smoke

```bash
tools/vm/run-single-vm-smoke.sh
```

This compiles, runs pytest, mounts FFSFS inside the guest, writes/reads/deletes a
file, unmounts, and prints the storage files found under `/tmp/ffsfs-storage`.

## Two-VM Peer Reachability

```bash
tools/vm/run-two-vm-test.sh
```

This boots two disposable overlays, syncs the repository into both guests,
starts peer HTTP servers without FUSE, verifies that each guest can reach the
other's `/healthz` endpoint through host-forwarded ports, then commits a
versioned file on peer A and fetches it from peer B through `/list-dir`, `/head`,
and `/get-file`.

Useful overrides:

```bash
FFSFS_VM_PEER_A_SSH_PORT=2222 \
FFSFS_VM_PEER_B_SSH_PORT=2223 \
FFSFS_VM_PEER_A_HOST_PORT=28765 \
FFSFS_VM_PEER_B_HOST_PORT=28766 \
tools/vm/run-two-vm-test.sh
```

## Logs

Per-run logs are written to `.vm/logs/<run-id>/`.

Archive a run:

```bash
tools/vm/collect-logs.sh <run-id>
```

## Environment Knobs

- `FFSFS_VM_STATE_DIR`
- `FFSFS_VM_BASE_IMAGE`
- `FFSFS_VM_IMAGE_URL`
- `FFSFS_VM_CPUS`
- `FFSFS_VM_MEMORY`
- `FFSFS_VM_SSH_PORT`
- `FFSFS_VM_SSH_WAIT_SECS`
- `FFSFS_VM_USER`
