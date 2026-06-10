# FFSFS Operator Guide

This guide describes operational procedures, configuration file formats, storage architecture, testing procedures, recovery workflows, and current limitations of FFSFS.

---

## 1) Configuration File Format

FFSFS supports explicit configuration files in JSON format. This allows configuring nodes, realms, and storage backends reproducibly.

### Example Configuration (`~/.ffsfs/myrealm.json`)

```json
{
  "realm": "myrealm",
  "realm_secret": "a1b2c3...64_hex_chars...",
  "node_name": "backup-node-1",
  "base": "/home/ubuntu/.myrealm",
  "mountpoint": "/home/ubuntu/myrealm",
  "port": 18765,
  "bind_host": "0.0.0.0",
  "autodiscover": true,
  "known_peers": [
    "host-b.local",
    "<host-c-lan-ip>"
  ],
  "peer_trust": "realm_secret",
  "trust_unknown_peers": false,
  "peer_transport": "http",
  "node_role": "replica_storage",
  "node_availability": "on_demand",
  "node_storage_profile": "bulk_storage",
  "sync": {
    "mode": "active",
    "prefixes": []
  }
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

Recommended setup and launch flow:

```bash
./setup.sh
./setup.sh --realm myrealm --check
./setup.sh --realm myrealm --activate
./launch.sh myrealm
```

Interpreter resolution: `setup.sh`/`launch.sh` use `FFSFS_PYTHON` if set, else a
project `./.venv`, else an active `$VIRTUAL_ENV`, else system `python3`.

**Run as a systemd service** (instead of a held-open terminal). One template
unit `ffsfs@.service`; each realm is the instance `ffsfs@<realm>`:

```bash
./service.sh install myrealm     # write unit + enable (user service by default)
./service.sh start   myrealm
./service.sh status  myrealm
./service.sh stop    myrealm     # SIGINT → clean unmount, forced unmount fallback
./service.sh uninstall myrealm
```

Default is a user service (`systemctl --user`, no root, starts on login;
`loginctl enable-linger "$USER"` to run without a login session). `--system`
installs a root system service but is discouraged (FUSE as root, reads `/root`
config) and warns first. The unit calls `launch.sh`, inheriting the same
interpreter resolution.

A venv is optional — system packages work without one. `./setup.sh` offers to
create the venv and install deps for you (default yes). To do it manually:

```bash
# python3-venv is required to build a venv; libfuse is always a system package
sudo apt install python3-venv libfuse2t64 fuse3
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt      # flask, requests, fusepy
```

`fusepy` is pure Python and works in a venv; only the FUSE C library
(`libfuse2t64`/`libfuse2`) must be a system package. If `python3-venv` is
missing, `python3 -m venv` fails and setup falls back to system Python. Set
`FFSFS_NO_VENV=1` to skip the venv prompt entirely.

**Using a Configuration File:**
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

### Web Dashboard
A running node serves human-facing pages on its peer port (localhost-only; use
an SSH tunnel for remote):

- `/dashboard` — peers, network summary, storage volumes (with ONLINE/OFFLINE/
  STALLED/PARKED status and free space), and sync status (failed paths,
  conflicts).
- `/dashboard/config` — applies peer-add live; shows copy-paste `ffsctl`/
  `configure.sh` commands for other changes.
- `/dashboard/logs` — recent in-process events with level filtering.

```bash
ssh -L 8765:localhost:<peer-port> user@node   # then open http://localhost:8765/dashboard
```

**Forgot the port?** The dashboard port is realm-derived (and falls back if
busy), so run the portal — a loopback-only, read-only landing page on a fixed
port that links to every realm's live dashboard:

```bash
./ffsportal.py            # then open http://127.0.0.1:4085/
```

It reads each node's `runtime.json` for the *actual* bound port and marks realms
live / stopped / inactive.

### Setup App

Use the console setup app for normal create/edit flows:

```bash
./setup.sh
./setup.sh --realm myrealm --check
./setup.sh --realm myrealm --activate
./setup.sh --list-devices
```

The setup app writes `realm-config.json` after each step but leaves the realm
inactive until validation and final activation. `launch.sh` refuses inactive
setup configs unless `--allow-inactive` is passed.

The setup flow records:

- host alias and admin password hash
- expected online pattern: always, hours/day, casual/on-demand, or unknown
- backend policy: greedy, redundancy-balanced, minimal, metadata/access-only,
  or capped by local cache size
- backend folders and mirror/media hints
- bandwidth/rate limits
- seed peers, including optional Tailscale interface discovery. Tailscale is
  treated as another reachable interface, not a separate trust mode; duplicate
  seed endpoints are ignored.

### Managing Peers Manually
Realm peer lists are stored in `realm-config.json`. Use `configure.sh` for
normal operation, or `ffsctl.py peer` directly when scripting lower-level
operations.

For multiple hosts on the same LAN, run `./setup.sh` on each host with the
same realm name and realm passphrase/key. Setup writes a deterministic peer
port into each realm config. Add each host's LAN address or hostname to the
other hosts. Use just `<hostname-or-ip>` for the normal same-realm default
port; use `<hostname-or-ip>:<port>` only when that peer was configured with a
non-default port:

```bash
./configure.sh add-peer myrealm host-b.local
./configure.sh add-peer myrealm <host-c-lan-ip>
```

Then activate and launch on each host:

```bash
./setup.sh --realm myrealm --activate
./launch.sh myrealm
```

Verify peer/sync state with:

```bash
python3 ffsctl.py sync myrealm status
```

- **List current peers:**
  ```bash
  ./configure.sh list-peers myrealm
  ```
- **Add a peer:**
  ```bash
  ./configure.sh add-peer myrealm <hostname-or-ip>
  ```
- **Remove a peer:**
  ```bash
  ./configure.sh remove-peer myrealm <hostname-or-ip>
  ```
- **Approve a peer node name** (needed when `peer_trust=manual`):
  ```bash
  ./configure.sh approve-peer myrealm node-b
  ```

---

## 2b) Peer Authentication

FFSFS uses HMAC request signing with a shared realm secret to authenticate
peer-to-peer communication. Every peer request includes a signature header that
proves the sender knows the realm secret.

### Generating a Realm Secret

A realm secret is automatically generated when you initialize a realm:

```bash
python3 ffsctl.py realm init myrealm --base ~/myrealm-storage
```

The secret is stored in `~/.ffsfs/.storage/myrealm/realm-config.json`.

### Sharing the Secret Between Nodes

There are three ways to get the same secret on multiple nodes:

**Option 1: Passphrase (easiest for humans)**

Use the same passphrase and realm name on each node. The secret is derived
deterministically (PBKDF2-SHA256, 600k iterations, realm name in salt):

```bash
# Node A:
python3 ffsctl.py realm init myrealm --passphrase "correct horse battery staple"

# Node B (same passphrase + realm name → same secret):
python3 ffsctl.py realm init myrealm --passphrase "correct horse battery staple"
```

**Option 2: Copy the hex secret**

Generate on one node, then pass the hex to the other:

```bash
# Node A — show the secret:
cat ~/.ffsfs/.storage/myrealm/realm-config.json | python3 -c "import sys,json; print(json.load(sys.stdin)['realm_secret'])"

# Node B — init with the same secret:
python3 ffsctl.py realm init myrealm --secret <paste-hex>
```

**Option 3: Update an existing node**

If a node already has a realm config, update the secret directly:

```bash
python3 ffsctl.py realm set myrealm realm_secret <hex-from-other-node>
```

Both nodes must have the identical `realm_secret` to exchange data.

### Trust Modes

Configure via `ffsctl.py realm set <realm> peer_trust <mode>`:

- **`realm_secret`** (default): Any peer that can sign requests with the realm
  secret is trusted to participate.
- **`manual`**: Peers must both know the realm secret AND be listed in the
  node's `approved_peers` list before data exchange is allowed.

Manage realm peer lists with:

```bash
./configure.sh list-peers myrealm
./configure.sh add-peer myrealm <hostname-or-ip>
./configure.sh remove-peer myrealm <hostname-or-ip>
./configure.sh approve-peer myrealm node-b
./configure.sh unapprove-peer myrealm node-b
```

`trust_unknown_peers` defaults to `false`, so authenticated unknown peers are
not automatically added to `known_peers`. For loose LAN testing, opt in with:

```bash
./configure.sh trust-unknown-peers myrealm true
```

### Transport

Configure via `ffsctl.py realm set <realm> peer_transport <mode>`:

- **`http`** (default): Plain HTTP. Authentication is via HMAC signatures, not
  transport encryption. Suitable for trusted LANs.
- **`https`**: TLS-encrypted transport. Provides confidentiality against passive
  network observers. HMAC auth is still required.

### What Auth Protects Against

- Random LAN devices joining your realm without the secret
- Forged sync/notify requests from unauthorized peers
- Replay attacks (nonce + timestamp checking)

### What Auth Does NOT Protect Against

- Passive network observation (use `peer_transport=https` for that)
- A compromised node that already has the secret
- Key rotation (not yet implemented — change the secret manually on all nodes)

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

`--max-file-size <n>` rejects that backend as the final storage target for any
single committed file larger than `n` bytes.

`--max-bytes <n>` rejects that backend as the final storage target when the
current bytes under its `.ffsfs_data/` plus the new committed file would exceed
`n` bytes.

`--reserve-bytes <n>` rejects that backend as the final storage target when the
filesystem free space after the commit would be below `n` bytes.

#### Editing a Registered Backend

`backend set` changes an existing backend's settings in place, addressed by
UUID, label, or path:

```bash
python3 ffsctl.py backend set myrealm backup-a --role cache --no-mirror
python3 ffsctl.py backend set myrealm backup-a --media hdd --device-class usb
python3 ffsctl.py backend set myrealm backup-a --max-bytes 0    # 0 clears a cap
```

It accepts the same policy flags as `add`, plus `--no-mirror` (turn
mirror-on-write off), `--device-class <class>` and `--job <prefix|none>`
(themed job prefix; `none` clears it). Size caps (`--max-bytes`,
`--max-file-size`, `--reserve-bytes`) are cleared with `0`. Invalid values are
rejected and change nothing, and the primary volume's role cannot be changed.

The interactive setup app (`python3 ffssetup.py`) offers the same per-backend
editing under "Edit a backend" (edit-menu item 5); blank answers keep the
current value. Either way, a running service applies backend edits on its next
restart.

#### How Writes Are Routed

New writes start as a temporary file on the current staging target:

1. If the primary backend is online, FFSFS writes to the primary.
2. If the primary is offline, FFSFS writes to the first online secondary.
3. If all configured volumes appear offline, FFSFS falls back to the primary
   path and lets the filesystem operation succeed or fail normally.

When the file is committed, FFSFS knows the final size. It then chooses the
final storage target among eligible online volumes, checking `max_file_size`,
`max_bytes`, `reserve_bytes`, and a default free-space floor
(`FFSFS_VOL_MIN_FREE_BYTES`, 256 MiB) so no drive is filled to the brim
(zero-byte markers bypass the floor). Among eligible volumes it prefers the one
with the **most free space**, so small or near-full drives are spared and writes
land where there is headroom (ties keep primary-first). Parked (ejected) volumes
are never chosen. If the staging target is not eligible but another online
backend is, FFSFS copies the completed file into the eligible backend and removes
the temp from the staging backend. If no online backend accepts the file, the
commit fails with a disk-space style error.

After the committed version exists on the final target, FFSFS copies that
version to every online backend marked `mirror: true`, except the volume that
already received the final commit.

This means:

- `--mirror` controls replication, not initial write-target priority.
- `--role archive` by itself does not mirror data. Add `--mirror` for catch-all
  backup/archive disks.
- Capacity options control final placement and can cause a commit to fail if
  no configured online backend can accept the file.
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

#### Parking a Backend (clean eject for rotation)

To take a removable disk offline cleanly while keeping it registered for next
time — the rotating-USB/archive workflow — park it instead of removing it:

```bash
python3 ffsctl.py backend eject  personal archive-a   # park; safe to unplug
python3 ffsctl.py backend attach personal archive-a   # un-park after re-plugging
```

A parked (`ejected`) backend stays in the config but receives no new writes;
missed writes are queued as pending replication and catch up after `attach`
once the volume is online again. `backend list` shows it as `[ONLINE/PARKED]`.
A running service applies eject/attach on its next restart. This is for the
*same* physical disk; rotating between *different* disks (distinct volume IDs)
is separate, still-evolving work.

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
        "max_file_size": 1099511627776,
        "max_bytes": 8000000000000,
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

## 3b) Redundancy Classes & Placement

By default every realm behaves as a blind mirror (`mirror` class): every node
pulls everything its sync policy wants. The redundancy feature lets you say,
per path prefix, how many copies the realm should keep instead. Full design:
`agents/redundancy_design.md`; current status: `agents/redundancy_handover.md`.

### Classes

- `mirror` — today's behavior, the default. Never auto-suggested, never reduced.
- `rf:N` — keep N copies on distinct nodes. Placement adds copies when below N.
- `cache` — no durable copy; fetch on demand, freely evictable. For large
  regenerable data (ISOs, model weights, video).

Configured in realm-config under `redundancy` (setup app: edit-menu item 15,
which can also scan existing files and suggest per-prefix classes from
size/type):

```json
"redundancy": {
  "default": "mirror",
  "overrides": { "photos": "rf:3", "iso": "cache" },
  "reconcile_interval": 300,
  "offline_grace": 604800,
  "reduction_margin": 2
}
```

### How placement works (add-only)

With an `rf:` class configured on a node whose role participates in placement,
a background worker periodically reconciles every local current version
against its target: nodes advertise what they hold (count + Bloom filter in
node-status), copies are only *counted* after a peer positively confirms them
(`/has-hashes`), and the lowest-id confirmed holder asks a suitable donor to
pull a copy (`/replicate-hint`, verified + pinned on the donor; eviction never
drops a pinned hash). Counting is availability-aware: a healthy placement
needs at least one copy on an online `always_online` node, and at most one
offline `on_demand` copy (a sleeping NAS) counts toward the target, for
`offline_grace` at most. Donors on a different host are preferred. When in
doubt — peer unreachable, Bloom ambiguity, stale state — the system always
errs toward an extra copy, never fewer.

The dashboard's Redundancy panel shows the last sweep, the at-risk list
(paths below target / without an always-on copy), recent placements, and the
per-node world map.

### Reducing surplus copies (operator-gated)

Placement only ever adds. Dropping a surplus local copy is a manual,
dry-run-first operation:

```bash
python3 ffsctl.py redundancy-reduce myrealm            # dry-run: what could drop, what is kept and why
python3 ffsctl.py redundancy-reduce myrealm --apply    # actually drop eligible local copies
```

A copy is only eligible when the path's class is `rf:N`, enough *other* nodes
confirmed online right now (at least N + `reduction_margin`), this node is the
designated dropper this round (highest node id — so two operators running it
simultaneously cannot drop the same file twice), dropping does not remove the
only always-on copy, and the file has no older local versions. Each drop is
re-confirmed against all peers immediately before it happens. The node must be
running; the realm always keeps at least the target number of copies.

---

## 4) VM Testing Procedure

To prevent mounting experimental FUSE systems directly on your developer workstation, FFSFS uses a QEMU-based VM test harness.

### 0. Run Local Baseline

Run this first after a checkout or code change. It is safe for the workstation
and does not mount FUSE:

```bash
python3 -m py_compile *.py
pytest
```

### 1. Build the Base VM Image
This downloads a cloud-init-enabled Ubuntu image and provisions it with FUSE, Python, and testing libraries:
```bash
tools/vm/build-base-image.sh
```

### 2. Run Single-VM Smoke Tests
This verifies basic FUSE filesystem mounting, writing, reading, deleting, and unmounting:
```bash
tools/vm/run-single-vm-smoke.sh
tools/vm/run-single-vm-pool-smoke.sh
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

- **No Direct Public Internet Support:** Do not expose the peer HTTP API
  directly on a public IP or router port-forward yet. The current security and
  resource model is intended for trusted LANs, isolated test networks, and
  private overlays. See `agents/public_internet_exposure.md` for the blocker
  analysis.
- **No Transport Encryption by Default:** Peer communication uses HTTP with HMAC request signing for authentication. File payloads and metadata are authenticated but not encrypted in transit. For confidentiality, configure `peer_transport=https` (requires manual cert setup) or use an encrypted overlay network like Tailscale.
- **Simple Conflict Resolution:** Conflicts are resolved via latest-timestamp-wins. Logical locking or interactive merge flows are not yet supported.
- **Auto-Discovery Limits:** UDP broadcast autodiscovery is designed for single-subnet LAN networks. Unknown peers are not auto-added by default; for multi-subnet or remote connections, add peers explicitly using `ffsctl.py peer <realm> add`.
- **Background Sync in Progress:** Explicit local mirror volumes have mirror-on-write plus pending catch-up retry. Final placement honors configured size/capacity limits. The next feature phase is implementing broader policies such as `cache_limited`, selected-prefix sync, media/role-aware routing, and eviction.
