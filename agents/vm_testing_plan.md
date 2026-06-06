# FFSFS VM Testing Plan

FFSFS should be tested in VMs before doing serious FUSE or peer-sync work on a
developer workstation. Custom FUSE mounts can hang, leave awkward mount state,
or interact badly with desktop file managers and indexing tools. A disposable VM
keeps those failures contained.

## Goals

- Keep the workstation stable while testing FUSE behavior.
- Make test runs disposable and repeatable.
- Support one-node mount tests and two-node peer/network tests.
- Keep fast unit tests separate from slower VM/integration tests.
- Preserve logs and storage artifacts from failed runs for debugging.

## Host Packages

Recommended Ubuntu host packages:

```bash
sudo apt update
sudo apt install \
  qemu-system-x86 \
  qemu-utils \
  cloud-image-utils \
  ovmf \
  genisoimage
```

Optional, but useful once the VM workflow grows:

```bash
sudo apt install \
  libvirt-daemon-system \
  libvirt-clients \
  virtinst \
  bridge-utils
```

Package roles:

- `qemu-system-x86`: runs x86_64 VMs.
- `qemu-utils`: provides `qemu-img` for qcow2 images and overlays.
- `cloud-image-utils`: provides `cloud-localds` for cloud-init seed images.
- `ovmf`: UEFI firmware for QEMU guests.
- `genisoimage`: ISO tooling used by some cloud-init/image workflows.
- `libvirt-*` and `virtinst`: easier VM/network lifecycle management.
- `bridge-utils`: bridge networking helper package.

## Guest Packages

Install these inside the test VM image:

```bash
sudo apt update
sudo apt install \
  git \
  python3 \
  python3-pytest \
  python3-flask \
  python3-requests \
  python3-fusepy \
  libfuse2t64 \
  fuse3
```

On older Ubuntu guests, use `libfuse2` instead of `libfuse2t64`.

The project uses the fusepy-style Python API. On Ubuntu/Debian this may import
as `fusepy`; upstream pip installs may import it as `fuse`. `crossfuse.py`
supports both names.

## Image Strategy

Use a read-only base qcow2 image plus disposable overlays:

```bash
qemu-img create -f qcow2 -F qcow2 -b base.qcow2 vm-a.qcow2
qemu-img create -f qcow2 -F qcow2 -b base.qcow2 vm-b.qcow2
```

For each test run:

1. Create fresh overlays.
2. Boot one or two VMs.
3. Copy or clone the repository into the guest.
4. Run tests over SSH.
5. Collect logs and artifacts.
6. Shut down the VMs.
7. Delete overlays unless debugging a failure.

## Current Harness

The first host-side scripts live under `tools/vm/`:

- `build-base-image.sh`: downloads and prepares the Ubuntu cloud base image.
- `run-one-vm.sh`: boots one disposable overlay, syncs the repo, and runs a
  configurable guest command.
- `run-single-vm-smoke.sh`: runs compile checks, pytest, and a FUSE
  write/read/delete smoke test inside one VM.
- `run-two-vm-test.sh`: boots two disposable VMs, starts peer HTTP servers, and
  verifies cross-guest `/healthz` reachability through host-forwarded ports.
- `collect-logs.sh`: archives logs from `.vm/logs/<run-id>/`.

Generated VM state defaults to `.vm/` and is ignored by git.

## Test Node Names

Use fixed names for automated VM tests:

- `ffsfs-vm-single`
- `ffsfs-vm-peer-a`
- `ffsfs-vm-peer-b`
- `ffsfs-vm-superpeer-a`

Manual real-world tests should use user-chosen names that match the actual
site, hardware, or role. Do not bake those names into automated tests.

## Test Configuration Profiles

Use simple config files as the foundation for reproducible tests. User tooling
can build on top later.

Suggested profiles:

- `vm-single`
- `vm-peer-a`
- `vm-peer-b`
- `vm-superpeer-a`

Each profile should make these values explicit:

- realm
- node name
- storage base
- mountpoint
- peer HTTP port
- bind host
- peer list
- autodiscovery enabled/disabled
- trust/test-mode settings

Automated VM tests should not depend on LAN broadcast, Tailscale, or real remote
hosts. Use an isolated VM network and explicit peers first. LAN and Tailscale
tests belong to later manual or deployment-specific test plans.

## Test Layers

### 1. Unit Tests

These can run on host and in VM. They must not mount FUSE.

Targets:

- filename parsing and building
- path normalization and containment
- temp filename generation
- storage backend commit behavior
- delete tombstone behavior
- peer cache/index helpers
- Flask route behavior via test client

Command:

```bash
pytest
```

### 2. Single-VM FUSE Tests

Run only in the VM.

Minimum smoke flow:

```bash
mkdir -p /tmp/ffsfs-mount
python3 ffsfs.py --base /tmp/ffsfs-storage --realm test /tmp/ffsfs-mount
echo hello > /tmp/ffsfs-mount/hello.txt
cat /tmp/ffsfs-mount/hello.txt
rm /tmp/ffsfs-mount/hello.txt
fusermount3 -u /tmp/ffsfs-mount
find /tmp/ffsfs-storage -type f -maxdepth 5
```

Expected coverage:

- import checks
- mount and unmount
- write/read
- delete
- version files created under storage, not mountpoint
- restart after unclean exit

### 3. Two-VM Peer Tests

Run with two disposable VMs on a private virtual network.

Minimum flow:

1. Boot VM A and VM B.
2. Start FFSFS on both with the same realm and separate storage.
3. Manually add peers or rely on discovery once discovery is reliable.
4. Write a file on VM A.
5. Read or fetch the file from VM B.
6. Delete or update the file on VM A.
7. Verify VM B observes the latest state.

Expected coverage:

- peer `/hello`
- peer `/status`
- peer `/list-files`
- peer `/head`
- peer `/get-file`
- notify/fetch behavior
- peer restart behavior

## Pytest Markers

Use markers to keep dangerous or slow tests explicit:

```text
unit
vm
fuse
network
two_peer
destructive
slow
```

Example commands:

```bash
pytest
pytest -m vm
pytest -m fuse
pytest -m two_peer
pytest -m destructive
```

## Proposed Repository Layout

```text
tests/
  unit/
    test_ffsutils.py
    test_storage_backend.py
    test_peer_api.py
  vm/
    test_mount_smoke.py
    test_write_read_delete.py
    test_two_peer_sync.py

tools/
  vm/
    build-base-image.sh
    run-one-vm.sh
    run-two-vm-test.sh
    collect-logs.sh
```

## First Implementation Steps

1. Add `pytest.ini` with markers.
2. Add unit tests for `ffsutils.py`.
3. Add storage backend tests that use `tmp_path`.
4. Create a single-VM boot script using a cloud image and cloud-init.
5. Add a VM smoke script that imports modules, mounts, writes, reads, unmounts,
   and collects logs.
6. Add a two-VM script with fixed SSH port forwards or a private libvirt
   network.
7. Add peer sync tests after the single-VM mount path is stable.

## Safety Rules

- Never run FUSE integration tests directly on the workstation by default.
- VM tests must create fresh mountpoints and storage directories per run.
- VM test scripts must attempt unmount on exit, but the VM overlay remains the
  real safety boundary.
- Keep failed overlays only when debugging; otherwise delete them automatically.
- Treat peer autodiscovery tests as network tests, not unit tests.
