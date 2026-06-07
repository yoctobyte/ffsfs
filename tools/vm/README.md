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

## Two-Peer Scenarios (Single VM)

```bash
tools/vm/run-two-peer-scenario.sh <scenario>
tools/vm/run-two-peer-scenario.sh smoke
tools/vm/run-two-peer-scenario.sh all
tools/vm/run-two-vm-test.sh   # compatibility wrapper: runs file-fetch
```

Both peer servers run as separate Python processes inside one disposable VM,
on different guest ports with different data directories. This keeps the TCG
boot cost to a single VM; a multi-VM layout is reserved for future stress
and config tests.

The runner boots one VM, syncs the repository, starts both peer servers
(without FUSE), waits for `/healthz` on each guest port, and sources the
named scenario. `smoke` and `all` keep that one VM running and reset the
peer data plus peer server processes between scenarios, avoiding one QEMU
boot per scenario while preserving scenario isolation. Inside the guest,
scenarios reach the peers over loopback:

- peer A: `http://127.0.0.1:$FFSFS_VM_PEER_A_PORT` (default `18765`)
- peer B: `http://127.0.0.1:$FFSFS_VM_PEER_B_PORT` (default `18766`)

Both peer ports are also forwarded to the host for ad-hoc debugging:

- peer A: `http://127.0.0.1:$FFSFS_VM_PEER_A_HOST_PORT` (default `28765`)
- peer B: `http://127.0.0.1:$FFSFS_VM_PEER_B_HOST_PORT` (default `28766`)

Available scenarios:

- `smoke`: a fast default batch; runs `healthz`, `file-fetch`,
  `delete-tombstone`, and `path-traversal` in one VM boot.
- `all`: every scenario under `tools/vm/scenarios/two-peer/`, sorted by name,
  in one VM boot.
- `healthz`: each peer reaches the other's `/healthz` endpoint over loopback.
- `file-fetch`: peer A commits a versioned file and peer B fetches it through
  `/list-dir`, `/head`, and `/get-file`.
- `delete-tombstone`: peer A creates, deletes, and recreates a file; peer B
  verifies visibility via `/list-dir`, `/head` (with `deleted` flag), and
  `/get-file` at each stage.

Useful overrides:

```bash
FFSFS_VM_TWO_PEER_NAME=ffsfs-vm-two-peer \
FFSFS_VM_TWO_PEER_SSH_PORT=2224 \
FFSFS_VM_PEER_A_PORT=18765 \
FFSFS_VM_PEER_B_PORT=18766 \
FFSFS_VM_PEER_A_HOST_PORT=28765 \
FFSFS_VM_PEER_B_HOST_PORT=28766 \
FFSFS_VM_PEER_A_DATA=/tmp/ffsfs-peer-data \
FFSFS_VM_PEER_B_DATA=/tmp/ffsfs-peer-data-b \
tools/vm/run-two-peer-scenario.sh delete-tombstone
```

Future scale work should build a separate N-node runner for 10+ node tests
(multiple VMs, real network topology). Keep that separate from the two-peer
runner so normal VM smoke runs stay fast and easy to diagnose.

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
