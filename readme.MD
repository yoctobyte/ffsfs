# FFSFS

FFSFS is an experimental distributed, versioned FUSE filesystem. It preserves
the virtual directory tree on disk and stores committed versions next to each
logical file.

This project is still rough. Treat it as a work in progress: test with scratch
data first, not irreplaceable files.

## Ubuntu Dependencies

The POSIX implementation uses the `fusepy`-style Python API:

```python
from fuse import FUSE, Operations, FuseOSError
```

That API is backed by the FUSE 2 userspace library, even on systems that also
have FUSE 3 installed.

On Ubuntu 24.04 and newer:

```bash
sudo apt update
sudo apt install python3-fusepy libfuse2t64 fuse3
```

On older Ubuntu releases, the FUSE 2 library package may be named `libfuse2`:

```bash
sudo apt update
sudo apt install python3-fusepy libfuse2 fuse3
```

`fuse3` is still useful for the system FUSE tooling, but it is not the Python
API used by this code.

Do not rely on Ubuntu's `python3-fuse` package for this project. It installs a
different, API-incompatible Python module named `fuse`. This code expects the
fusepy API with `FUSE`, `Operations`, and `FuseOSError`.

Verify the expected Python import:

```bash
python3 - <<'PY'
try:
    from fuse import FUSE, Operations, FuseOSError
    print("fusepy API available as fuse")
except ImportError:
    from fusepy import FUSE, Operations, FuseOSError
    print("fusepy API available as fusepy")
PY
```

Other Python dependencies currently used by the peer layer:

```bash
sudo apt install python3-flask python3-requests
```

## Quick Start

Short form:

```bash
python3 ffsfs.py myrealm
```

This uses:

- mountpoint: `~/myrealm`
- storage: `~/.myrealm/myrealm`
- peer port: stable hash of the realm, with fallback if the port is busy

Full form:

```bash
mkdir -p /tmp/ffsfs-mount
python3 ffsfs.py --base /tmp/ffsfs-storage --realm myrealm /tmp/ffsfs-mount
```

The mountpoint must be an empty directory. Keep the storage directory outside
the mountpoint.

## Useful Commands

Local verification:

```bash
python3 -m py_compile *.py
pytest
```

VM verification:

```bash
tools/vm/run-single-vm-smoke.sh
tools/vm/run-two-peer-scenario.sh file-fetch
tools/vm/run-two-peer-scenario.sh delete-tombstone
```

The two-peer runner boots a single disposable VM and starts two peer
processes on different guest ports. Multi-VM is reserved for stress tests.

Check peer status:

```bash
python3 ffsctl.py status --port 8765
```

Manage peers:

```bash
python3 ffsctl.py peers list
python3 ffsctl.py peers add 192.168.1.12:8765
python3 ffsctl.py peers remove 192.168.1.12:8765
```

Unmount manually on Linux:

```bash
fusermount3 -u <mountpoint>
```

or, depending on the system:

```bash
fusermount -u <mountpoint>
```

## More Detail

See `tech_doc.md` for the storage layout, filename schema, peer HTTP API,
autodiscovery protocol, tunables, and state files.

Project planning and agent coordination docs live under `agents/`.

## Roadmap

Current priority is testing and correctness:

- grow two-peer VM scenarios for update, path-traversal, and peer
  restart behavior (delete-tombstone scenario is done)
- tighten peer delete/tombstone semantics: /notify NULL_HASH normalization
  and notify propagation timing
- improve VM scenario runner ergonomics and failure summaries
- normalize CLI/config files for reproducible realms and test profiles
- reduce silent failures in write/delete/sync/notify/startup paths

The next major feature track after testing/config is policy-driven background
synchronization. Planned node roles include access-only/cache-only laptops,
limited shared-storage boxes, superpeers, and NAS/file-server profiles. Planned
sync policies include disabled, selected prefixes, whole-realm where feasible,
opportunistic sync for sometimes-online boxes, scheduled windows, and eventual
redundancy targets.
