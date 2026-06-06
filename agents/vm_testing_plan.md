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
- `run-two-vm-test.sh`: boots two disposable VMs, starts peer HTTP servers,
  and runs the default two-peer scenario.
- `run-two-peer-scenario.sh`: boots two disposable VMs and runs a named scenario
  from `tools/vm/scenarios/two-peer/`, such as `healthz` or `file-fetch`.
- `collect-logs.sh`: archives logs from `.vm/logs/<run-id>/`.

Generated VM state defaults to `.vm/` and is ignored by git.

## Test Node Names

Use fixed names for automated VM tests:

- `ffsfs-vm-single`
- `ffsfs-vm-peer-a`
- `ffsfs-vm-peer-b`
- `ffsfs-vm-superpeer-a`

Future scale tests should add generated names for larger clusters, such as
`ffsfs-vm-scale-01` through `ffsfs-vm-scale-10`. Keep those in a separate
N-node runner so 10+ node tests do not make two-peer smoke tests slower or more
fragile.

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

## Repository Layout

```text
tests/
  test_ffsutils.py
  test_storage_backend.py
  test_ffspeers_api.py

tools/
  vm/
    build-base-image.sh
    common.sh
    two-peer-common.sh
    run-one-vm.sh
    run-single-vm-smoke.sh
    run-two-vm-test.sh
    run-two-peer-scenario.sh
    collect-logs.sh
    scenarios/two-peer/
      healthz.sh
      file-fetch.sh
```

## Current Commands

Build the base image:

```bash
tools/vm/build-base-image.sh
```

Run local tests inside one disposable VM:

```bash
tools/vm/run-one-vm.sh
```

Run the FUSE smoke in one disposable VM:

```bash
tools/vm/run-single-vm-smoke.sh
```

Run two-peer scenarios:

```bash
tools/vm/run-two-peer-scenario.sh healthz
tools/vm/run-two-peer-scenario.sh file-fetch
```

Compatibility wrapper:

```bash
tools/vm/run-two-vm-test.sh
```

## Next Implementation Steps

1. Add `run-two-peer-scenario.sh all`.
2. Add scenario timeouts and concise failure summaries.
3. Add two-peer scenarios:
   - update-newer-version
   - delete-tombstone
   - path-traversal
   - peer-restart
4. Decide whether later peer-network tests should stay on QEMU user-mode port
   forwarding or move to a private bridge/libvirt network.
5. Add an N-node runner later for 10+ node scale tests.

## Safety Rules

- Never run FUSE integration tests directly on the workstation by default.
- VM tests must create fresh mountpoints and storage directories per run.
- VM test scripts must attempt unmount on exit, but the VM overlay remains the
  real safety boundary.
- Keep failed overlays only when debugging; otherwise delete them automatically.
- Treat peer autodiscovery tests as network tests, not unit tests.
