# FFSFS

FFSFS is an experimental distributed, versioned FUSE filesystem. It preserves
the virtual directory tree on disk and stores committed versions next to each
logical file under `.ffsfs_data/`.

This project is still prototype-quality. Test with scratch data first, not
irreplaceable files.

## Install Dependencies

FFSFS is intended to run against the system Python and system FUSE libraries.
A virtualenv is usually not needed and can make FUSE setup more confusing,
because the important pieces are OS packages, not pip-only packages.

On Ubuntu 24.04 and newer:

```bash
sudo apt update
sudo apt install python3-fusepy libfuse2t64 python3-flask python3-requests
```

On older Ubuntu releases, the FUSE 2 library package may be named `libfuse2`:

```bash
sudo apt update
sudo apt install python3-fusepy libfuse2 python3-flask python3-requests
```

FFSFS uses the `fusepy` API exposed as Python module `fuse`:

```python
from fuse import FUSE, Operations, FuseOSError
```

Do not install Ubuntu's `python3-fuse` package for this project. It provides a
different, incompatible Python API. The `fuse3` package is not required by
FFSFS, but it can be useful for recovery tooling such as `fusermount3` if your
system does not already provide it.
`fusermount3` can detach a stuck or crashed FUSE mount, including with lazy
unmount mode (`-z`) when the mountpoint is still busy.

Verify the import:

```bash
python3 - <<'PY'
from fuse import FUSE, Operations, FuseOSError
print("fusepy API available")
PY
```

## Quick Start

There are two supported ways to run FFSFS.

### Option 1: Direct Python Command

Short realm form:

```bash
python3 ffsfs.py myrealm
```

This uses:

- mountpoint: `~/myrealm`
- storage: `~/.myrealm/myrealm`
- peer port: stable hash of the realm, with fallback if the port is busy

Explicit form:

```bash
mkdir -p /tmp/ffsfs-mount
python3 ffsfs.py --base /tmp/ffsfs-storage --realm myrealm /tmp/ffsfs-mount
```

The mountpoint must be an empty directory. Keep the storage directory outside
the mountpoint.

### Option 2: Setup Then Launch

This is the recommended operator flow for repeatable realms:

```bash
./setup.sh
./launch.sh myrealm
```

Run in the background:

```bash
./launch.sh myrealm --bg
```

If exactly one realm is configured, `./launch.sh` can be run without a realm
argument. With multiple configured realms, pass the realm explicitly.

Useful setup commands:

```bash
./setup.sh --realm myrealm --check
./setup.sh --realm myrealm --activate
./setup.sh --list-devices
```

The setup app asks for node online expectations, storage/backend policy,
optional bandwidth limits, and seed peers. It can also list mounted devices and
import Tailscale interface addresses as ordinary seed hosts when the
`tailscale` CLI is available.

The config file lives at:

```text
~/.ffsfs/.storage/<realm>/realm-config.json
```

## Storage Backends

A realm has one primary backend and can have additional storage backends.
The primary backend stores authoritative metadata and is the preferred write
target while it is online.

Add a mirrored archive disk:

```bash
python3 ffsctl.py backend add myrealm /media/backup-a/ffsfs \
  --id backup-a \
  --role archive \
  --mirror \
  --media hdd
```

Equivalent helper command:

```bash
./configure.sh add-backend myrealm /media/backup-a/ffsfs \
  --id backup-a \
  --role archive \
  --mirror \
  --media hdd
```

Inspect backends:

```bash
python3 ffsctl.py backend list myrealm
./configure.sh list-backends myrealm
```

Remove a backend from config without deleting files on disk:

```bash
python3 ffsctl.py backend remove myrealm backup-a
```

Backend option summary:

- `--id <label>`: human label; remove can use UUID, label, or path.
- `--role archive|cache`: records intended use. `archive` is for durable
  storage; `cache` is for cache-like storage.
- `--mirror`: copy committed versions to this backend when online; missed
  copies are retried later.
- `--media ssd|hdd|network`: stored as a media hint for policy decisions.
- `--max-file-size <bytes>`: do not place files larger than this on the backend.
- `--max-bytes <bytes>`: do not place files if backend usage would exceed this.
- `--reserve-bytes <bytes>`: keep this much free space on the backend.

Writes start on the current staging target, usually the primary. At commit time
FFSFS knows the final file size and chooses an eligible final backend using the
capacity options above. After that, online `--mirror` backends receive a copy.
If a mirror is offline, the missed copy is recorded in:

```text
<primary-backend>/.ffsfs-pending-replication.jsonl
```

The mounted filesystem retries pending mirror copies periodically.

See [agents/operator_guide.md](agents/operator_guide.md) for detailed backend
configuration examples and the JSON schema.

## Peers

Check peer status:

```bash
python3 ffsctl.py status --port 8765
```

Manage peers:

```bash
./configure.sh list-peers myrealm
./configure.sh add-peer myrealm 192.168.1.12:8765
./configure.sh remove-peer myrealm 192.168.1.12:8765
./configure.sh approve-peer myrealm node-b
```

Unknown peers are not auto-added by default. For loose LAN testing only:

```bash
./configure.sh trust-unknown-peers myrealm true
```

Peer networking is still prototype-grade and intended for trusted LAN or
private overlay networks.

Do not expose the peer HTTP API directly on a public IP or router port-forward
yet. Public Internet support needs additional transport, identity, DoS, and
peer-scaling hardening; see
[agents/public_internet_exposure.md](agents/public_internet_exposure.md).

## Unmounting

Unmount manually on Linux:

```bash
fusermount -u <mountpoint>
```

On systems with FUSE 3 tooling available, this may also work:

```bash
fusermount3 -u <mountpoint>
```

If the mount is stuck:

```bash
fusermount -u -z <mountpoint>
```

or:

```bash
fusermount3 -u -z <mountpoint>
```

## Verification

Local unit tests do not mount FUSE on the workstation:

```bash
python3 -m py_compile *.py
pytest
```

VM verification uses disposable QEMU guests:

```bash
tools/vm/run-single-vm-smoke.sh
tools/vm/run-single-vm-pool-smoke.sh
tools/vm/run-two-peer-scenario.sh smoke
tools/vm/run-two-peer-scenario.sh all
```

The two-peer runner boots one disposable VM and starts two peer processes on
different guest ports. Multi-VM tests are reserved for future stress testing.

## More Detail

- [agents/operator_guide.md](agents/operator_guide.md): operator workflows,
  backend configuration, VM testing, and recovery.
- [tech_doc.md](tech_doc.md): storage layout, filename schema, peer HTTP API,
  autodiscovery protocol, tunables, and state files.
- [agents/](agents/): project plans and agent coordination notes.
