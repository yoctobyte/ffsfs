# FFSFS Operator Guide

This guide describes operational procedures, configuration file formats, storage architecture, testing procedures, recovery workflows, and current limitations of FFSFS.

---

## 1) Configuration File Format

FFSFS supports explicit configuration files in JSON format. This allows configuring nodes, realms, and storage backends reproducibly.

### Example Configuration (`~/.ffsfs/myrealm.json`)

```json
{
  "realm": "myrealm",
  "node_name": "backup-node-1",
  "base": "/home/ubuntu/.myrealm",
  "mountpoint": "/home/ubuntu/myrealm",
  "port": 18765,
  "bind_host": "0.0.0.0",
  "autodiscover": true,
  "known_peers": [
    "192.168.1.50:18765",
    "192.168.1.51:18765"
  ],
  "storage_role": "superpeer",
  "sync_policy": "all"
}
```

### Configuration Resolution Precedence
When starting the FFSFS daemon, parameters are resolved in the following priority order:
1. **Command Line Arguments** (e.g. `--realm`, `--base`, `--port`, `--bg`)
2. **Configuration File** (`--config <path>`)
3. **Environment variables** (e.g. `FFSFS_REALM`, `FFSFS_PEER_PORT`, `FFSFS_PEER_HOST`, `FFSFS_AUTODISCOVER`)
4. **Built-in Defaults** (e.g. `DATA_DIR = ".ffsfs_data"`, `PEER_PORT = 8765`, `AUTO_DISCOVER = true`)

---

## 2) Operator Workflow

### Launching FFSFS

**Using a Configuration File (Recommended):**
```bash
python3 ffsfs.py --config ~/.ffsfs/myrealm.json
```

**Running in the Background:**
```bash
python3 ffsfs.py --config ~/.ffsfs/myrealm.json --bg
```

**Short/Fast Launch (Auto-generates mountpoint and port based on realm):**
```bash
python3 ffsfs.py myrealm
```
This automatically mounts at `~/myrealm` and stores data at `~/.myrealm/myrealm`.

### Querying Node Status
To check the status of the local node and its connected peers, use `ffsctl.py`:
```bash
python3 ffsctl.py status --port 18765
```

### Managing Peers Manually
Peers list is stored in `.storage/peers-<realm>.conf`. You can manipulate this config file directly or use `ffsctl.py`:
- **List current peers:**
  ```bash
  python3 ffsctl.py peers list --conf ~/.ffsfs/.storage/peers-myrealm.conf
  ```
- **Add a peer:**
  ```bash
  python3 ffsctl.py peers add 192.168.1.52:18765 --conf ~/.ffsfs/.storage/peers-myrealm.conf
  ```
- **Remove a peer:**
  ```bash
  python3 ffsctl.py peers remove 192.168.1.52:18765 --conf ~/.ffsfs/.storage/peers-myrealm.conf
  ```
- **Ban a peer** (adds it to a blacklist to block future gossips/syncs):
  ```bash
  python3 ffsctl.py peers ban 192.168.1.99:18765 --conf ~/.ffsfs/.storage/peers-myrealm.conf
  ```

---

## 3) Storage Layout & Format

FFSFS preserves the virtual directory structure on disk. Unlike object stores that flatten paths, FFSFS directories correspond directly to your logical file system.

### On-Disk Directory Structure
For a mount point at `~/myrealm/` containing files `docs/notes.txt` and `photo.jpg`, the storage base directory (e.g. `~/.myrealm/myrealm/`) contains:

```
~/.myrealm/myrealm/
├── .ffsfs                      <-- Magic marker file containing realm JSON metadata
├── .ffsfs-meta.log             <-- Append-only authoritative metadata log
└── .ffsfs_data/
    ├── docs/
    │   ├── notes.txt.1X3P3...write.0.1780815915    <-- Regular version file
    │   └── notes.txt.1RXGR...delete.0.1780816075   <-- Delete tombstone version file
    └── photo.jpg.1CCZH...write.0.1780815435
```

### Version Filename Schema
Each file version is stored as:
`<logical_basename>.<HASH>.<mode>.<uid>.<timestamp>`
- **HASH**: Crockford Base32 representation of the content hash.
- **mode**: `write` for regular content, `delete` for a tombstone.
- **uid**: Revision index or author identifier (defaults to `0`).
- **timestamp**: Unix epoch time of creation.

### Durability Guarantees
- Local write operations (`flush`, `fsync`, `release`, and `rename`) are synchronous. If the underlying disk is full (`ENOSPC`) or write permissions are lost (`EACCES`), the error propagates up to FUSE and is raised in the calling application.
- File descriptor and handle cleanup are wrapped in `finally` blocks, meaning resources are freed even on failed commits.
- Peer sync operations are **best-effort**. Network drops or peer timeouts will produce warning logs but will never block local write completion, ensuring offline-first functionality.

### Backend Configuration
Storage backends are configured per realm. A realm has one primary backend and
zero or more additional backends.

```bash
python3 ffsctl.py realm init myrealm --mountpoint ~/myrealm --base ~/.myrealm
python3 ffsctl.py backend add myrealm /media/backup-a/ffsfs --id backup-a --role archive --mirror --media hdd
python3 ffsctl.py backend list myrealm
```

The primary backend is created by `realm init --base`. It stores the
authoritative metadata log and is the preferred write target while it is online.
Additional backends are registered with `backend add`.

#### Backend Options

`--id <label>` sets a human label. It is not the UUID in `.ffsfs-volume.id`.
You can remove a backend by UUID, label, or path.

`--role <role>` records the intended role. Current values are `archive` and
`cache`; `primary` is reserved for the primary backend. Today this is mostly
descriptive except where future policy will use it. Use `archive` for large
durable disks and `cache` for local scratch/cache storage.

`--mirror` enables mirror-on-write for that backend. Each committed version file
is copied to every online mirror backend. If the mirror is offline, the write
still succeeds after the selected write target commits, and the missed copy is
recorded for later catch-up.

`--media <ssd|hdd|network>` stores a media hint. It is visible in config and
`backend list`, but it does not yet change routing. Use it now so future
policy-driven routing can distinguish fast SSDs, slower HDDs, and network
storage.

`--max-bytes <n>`, `--max-file-size <n>`, and `--reserve-bytes <n>` store
capacity hints. They do not yet enforce limits or change write routing. They
are included so configurations can be written before the policy engine lands.

#### How Writes Are Routed

New writes are committed to one write target first:

1. If the primary backend is online, FFSFS writes to the primary.
2. If the primary is offline, FFSFS writes to the first online secondary.
3. If all configured volumes appear offline, FFSFS falls back to the primary
   path and lets the filesystem operation succeed or fail normally.

After the committed version exists on the write target, FFSFS copies that
version to every online backend marked `mirror: true`, except the volume that
already received the write.

This means:

- `--mirror` controls replication, not initial write-target priority.
- `--role archive` by itself does not mirror data. Add `--mirror` for catch-all
  backup/archive disks.
- Multiple online mirrors all receive a copy of the same committed version.
- A write is considered locally successful once the write target commit
  succeeds. Mirror copy failures are logged and recorded for retry.

#### Offline Mirrors and Catch-Up

Missed mirror copies are stored in:

```text
<primary-backend>/.ffsfs-pending-replication.jsonl
```

While the filesystem is mounted, FFSFS periodically retries pending mirror
copies. You can also trigger the same logic from Python for diagnostics:

```bash
python3 - <<'PY'
from ffsfs import StorageBackend
from ffsvolumes import load_pool_config

cfg = "/home/user/.ffsfs/.storage/myrealm/realm-config.json"
pool = load_pool_config(cfg)
backend = StorageBackend(pool.primary.path, "myrealm", pool=pool)
print(backend.sync_pending_replication())
PY
```

Catch-up copies from any online volume that already has the requested version,
not only from the primary. This is useful when the primary was offline during
the original write and another backend received the committed file.

#### Common Configurations

Single local SSD, no extra copies:

```bash
python3 ffsctl.py realm init personal --mountpoint ~/personal --base ~/.personal
```

Laptop SSD plus one external backup disk:

```bash
python3 ffsctl.py realm init personal --mountpoint ~/personal --base ~/.personal
python3 ffsctl.py backend add personal /media/backup-a/ffsfs --id backup-a --role archive --mirror --media hdd
```

SSD plus two catch-all archive disks:

```bash
python3 ffsctl.py backend add personal /media/archive-a/ffsfs --id archive-a --role archive --mirror --media hdd
python3 ffsctl.py backend add personal /media/archive-b/ffsfs --id archive-b --role archive --mirror --media hdd
```

Cache-like secondary, not a durable mirror:

```bash
python3 ffsctl.py backend add personal /mnt/fast-cache/ffsfs --id fast-cache --role cache --media ssd
```

#### Inspecting and Removing Backends

```bash
python3 ffsctl.py backend list personal
python3 ffsctl.py backend remove personal archive-a
```

Removing a backend only detaches it from the realm config. It does not delete
files from the backend path.

#### Configuration Schema

Backend configuration is stored in
`~/.ffsfs/.storage/<realm>/realm-config.json`:

```json
{
  "realm": "personal",
  "mountpoint": "/home/user/personal",
  "base": "/home/user/.personal",
  "storage_pool": {
    "primary": {
      "id": "primary-uuid",
      "path": "/home/user/.personal",
      "label": "personal-primary",
      "role": "primary",
      "mirror": false
    },
    "backends": [
      {
        "id": "archive-uuid",
        "path": "/media/archive-a/ffsfs",
        "label": "archive-a",
        "role": "archive",
        "mirror": true,
        "media": "hdd",
        "reserve_bytes": 10737418240
      }
    ]
  }
}
```

Each backend path also contains `.ffsfs-volume.id`. FFSFS considers a backend
online only when the directory exists, that file exists, and the ID inside it
matches the ID in the realm config. This prevents accidentally writing to the
wrong mounted disk path.

---

## 4) VM Testing Procedure

To prevent mounting experimental FUSE systems directly on your developer workstation, FFSFS uses a QEMU-based VM test harness.

### 1. Build the Base VM Image
This downloads a cloud-init-enabled Ubuntu image and provisions it with FUSE, Python, and testing libraries:
```bash
tools/vm/build-base-image.sh
```

### 2. Run Single-VM Smoke Tests
This verifies basic FUSE filesystem mounting, writing, reading, deleting, and unmounting:
```bash
tools/vm/run-single-vm-smoke.sh
```

### 3. Run Two-Peer Network Scenarios
This boots a VM containing two FFSFS guest peer nodes on different ports and runs automated sync scenarios:
```bash
# Run all scenarios:
tools/vm/run-two-peer-scenario.sh all

# Run a specific scenario:
tools/vm/run-two-peer-scenario.sh peer-restart
```
Guest logs are automatically aggregated on the host under `.vm/logs/two-peer-<timestamp>/` on test completion.

---

## 5) Stuck Mount Recovery

FUSE filesystems can sometimes hang or get stuck in a "Transport endpoint is not connected" state if the daemon crashes or is forcefully terminated.

### Recovery Steps:

1. **Standard Unmount:**
   ```bash
   fusermount3 -u ~/myrealm
   ```
   If using FUSE 2 tooling, run:
   ```bash
   fusermount -u ~/myrealm
   ```

2. **Lazy/Force Unmount:**
   If the mountpoint is busy, use the lazy option to detach the mountpoint immediately and clean up resource references as soon as they are no longer busy:
   ```bash
   fusermount3 -u -z ~/myrealm
   ```

3. **PID File Cleanup:**
   If the daemon was started using `ffsctl.py start`, remove the leftover PID tracking file:
   ```bash
   rm -f ~/.ffsfs/.ffsfs.pid
   ```

---

## 6) Known Limitations

- **No Encryption/Authentication:** The current prototype sends file payloads and metadata in plaintext over HTTP/UDP. It is meant for trusted LANs or private overlay networks (like Tailscale).
- **Simple Conflict Resolution:** Conflicts are resolved via latest-timestamp-wins. Logical locking or interactive merge flows are not yet supported.
- **Auto-Discovery Limits:** UDP broadcast autodiscovery is designed for single-subnet LAN networks. For multi-subnet or remote connections, you must add peers manually using `ffsctl.py peers add`.
- **Background Sync in Progress:** Explicit local mirror volumes have mirror-on-write plus pending catch-up retry. The next feature phase is implementing broader policies such as `cache_limited`, selected-prefix sync, eviction, and capacity-aware routing.
