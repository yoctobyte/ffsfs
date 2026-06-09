# FFSFS

FFSFS is an experimental distributed, versioned FUSE filesystem. It preserves
the virtual directory tree on disk and stores committed versions next to each
logical file under `.ffsfs_data/`.

This project is still prototype-quality. Test with scratch data first, not
irreplaceable files.

## Quick Install (Ubuntu)

> ⚠️ **Do not connect this service to the Internet.** FFSFS is for trusted LAN /
> private overlay networks only — no public IP, no port-forwarding. See
> [Security Scope](#security-scope--read-first).

Impatient path for a typical Ubuntu 24.04+ box. If anything here misbehaves, use
the detailed steps under [Install](#install).

Install (creates a realm interactively; offers a venv, default yes):

```bash
sudo apt update
sudo apt install -y git python3-fusepy libfuse2t64 python3-flask python3-requests fuse3
git clone https://github.com/yoctobyte/ffsfs.git
cd ffsfs
./setup.sh
```

Then run it, using the realm name you chose during setup:

```bash
./launch.sh <your-realm>
```

## Security Scope — Read First

FFSFS is designed and tested for **trusted LAN or private overlay networks
only**. It is not hardened for hostile networks. Treat the following as hard
rules, not suggestions:

- **Never expose FFSFS to the public Internet.** Do not port-forward, reverse-
  proxy, or bind the peer HTTP API to a public IP.
- **Run experiments in virtual machines.** The VM test harness exists for this
  reason; prefer it over the workstation.
- **Run on your own LAN at your own risk.** You are advised to disconnect the
  testing LAN from the Internet while evaluating FFSFS.
- The peer transport is plaintext HTTP authenticated by a shared per-realm HMAC
  secret. There is no transport encryption, no per-node identity, and no
  response-body signing. Anyone with the realm secret has full read/write
  access to the whole realm. Anyone on the LAN segment can observe traffic.
- The realm secret is stored in the realm config file. Protect that file and the
  host it lives on accordingly.

Public Internet support is explicitly out of scope until the hardening blockers
in [agents/public_internet_exposure.md](agents/public_internet_exposure.md) are
addressed.

## Install

Get the code (run FFSFS straight from the checkout — nothing is written back
into the repo):

```bash
git clone https://github.com/yoctobyte/ffsfs.git
cd ffsfs
```

To update later:

```bash
git pull          # then restart: ./launch.sh <realm>
```

### Dependencies

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

### Optional: virtualenv

You usually don't set this up yourself: `./setup.sh` offers to create a `.venv`
and install the Python deps for you (default yes), and `launch.sh`/`setup.sh`
then use it automatically. The system FUSE library
(`libfuse2t64`/`libfuse2`) is still an `apt` package either way. See
[agents/operator_guide.md](agents/operator_guide.md) for manual venv setup and
the `FFSFS_PYTHON` override.

## Quick Start

The recommended user path is:

```bash
./setup.sh
./launch.sh myrealm
```

Use scratch data first. FFSFS is still prototype-quality.

### Direct Python Command

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

### Setup Then Launch

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
collaboration intent, optional bandwidth limits, and seed peers. It can also
list mounted devices and import Tailscale interface addresses as ordinary seed
hosts when the `tailscale` CLI is available.

Setup also records *intent* so behavior can be tuned later:

- **Collaboration** (`solo` or `shared`, default `solo`). `solo` is a single
  curator (last-write-wins, conflicts only warned); `shared` anticipates
  multiple writers (conflicts surfaced). This is recorded now; richer
  conflict resolution per mode is future work.
- **Per-backend device class** (`internal`, `usb`, `sd`, `optical`, `network`).
  Setup suggests sensible defaults per class — for example, removable USB/SD
  keys default to mirrored backup with a small max file size — and you can
  assign a themed job (e.g. "music only", scoped to a `/music` prefix). The
  size cap is enforced today; theme/prefix write-routing is future work.

`setup.sh` saves after each step but marks a realm inactive until activation.
`launch.sh` refuses inactive setup configs unless `--allow-inactive` is passed.

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

Park a backend for clean removal (e.g. a rotated USB/archive disk) without
unregistering it — it receives no new writes, stays in the config, and catches
up missed writes when re-attached:

```bash
python3 ffsctl.py backend eject  myrealm backup-a    # park; safe to unplug
python3 ffsctl.py backend attach myrealm backup-a    # un-park after re-plugging
# helper equivalents:
./configure.sh eject-backend  myrealm backup-a
./configure.sh attach-backend myrealm backup-a
```

A running service applies eject/attach on its next restart. `backend list`
shows a parked volume as `[ONLINE/PARKED]`.

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

Even without `--reserve-bytes`, every volume keeps a default free-space floor
(256 MiB, set via `FFSFS_VOL_MIN_FREE_BYTES`) so a drive is never filled to the
brim; zero-byte markers (deletes/move hints) bypass it. Writes prefer the online
volume with the most free space, so small or near-full drives are spared.

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

For two or more hosts on the same LAN:

1. Run `./setup.sh` on each host.
2. Use the same realm name and the same realm passphrase/key on every host.
3. Add each other host as a seed peer. Use just `<hostname-or-ip>` for the
   normal same-realm default port. Use `<hostname-or-ip>:<port>` only when that
   peer was configured with a non-default port:

   ```bash
   ./configure.sh add-peer myrealm host-b.local
   ./configure.sh add-peer myrealm <host-c-lan-ip>
   ```

5. Activate and launch each host:

   ```bash
   ./setup.sh --realm myrealm --activate
   ./launch.sh myrealm
   ```

Check sync/peer status:

```bash
python3 ffsctl.py sync myrealm status
```

Manage peers:

```bash
./configure.sh list-peers myrealm
./configure.sh add-peer myrealm <hostname-or-ip>
./configure.sh remove-peer myrealm <hostname-or-ip>
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

## Dashboard

A running peer node serves two human-facing web pages on its peer port:

- `/dashboard` — read-only overview: known peers, sync status (failed paths and
  conflicts), storage volumes with live status (ONLINE / OFFLINE / **STALLED**)
  and free space, plus realm/auth metadata.
- `/dashboard/config` — applies peer-add immediately; for everything else
  (backends, roles, sync policy, rate limits) it shows the exact
  `ffsctl`/`configure.sh` command to copy, run, and then restart the service.

```text
http://localhost:<peer-port>/dashboard
```

The dashboard is **localhost-only**. A browser cannot sign the peer HMAC, so the
pages are reached from the machine itself or over an SSH tunnel:

```bash
ssh -L 8765:localhost:<peer-port> user@node   # then open http://localhost:8765/dashboard
```

Remote access with a session password is a planned follow-up; until then it is
loopback-gated. The dashboard reads volume status from a non-blocking liveness
cache, so a stalled or unplugged backend never freezes the page or the service.

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

Run the local baseline before trusting a checkout or after changing code. These
tests do not mount FUSE on the workstation:

```bash
python3 -m py_compile *.py
pytest
```

Run VM verification before trusting FUSE behavior, peer networking, or release
candidate changes. VM tests use disposable QEMU guests:

```bash
tools/vm/run-single-vm-smoke.sh
tools/vm/run-single-vm-pool-smoke.sh
tools/vm/run-two-peer-scenario.sh smoke
tools/vm/run-two-peer-scenario.sh all
```

The two-peer runner boots one disposable VM and starts two peer processes on
different guest ports. Multi-VM tests are reserved for future stress testing.

Normal local development should not mount test FUSE filesystems directly on the
workstation.

## Upgrading & Data Persistence

FFSFS is built so a live node can track the repo and upgrade with just:

```bash
git pull
./launch.sh myrealm      # restart; no reconfiguration needed
```

This works because **all state lives outside the git checkout**, so you can run
FFSFS straight from the working repo without polluting it:

- **Config:** `~/.ffsfs/.storage/<realm>/realm-config.json` (per realm).
- **Node state:** peer list, instance/storage IDs, gossip seeds, and
  subscriptions live under `~/.ffsfs/.storage/` too (override the base with
  `FFSFS_STATE_DIR`). These are never written into the current directory.
- **Data:** under each backend path you configured (the primary base and any
  added backends), in the plain, versioned on-disk layout.

`git pull` only updates code; it never touches your config, node state, or data,
and nothing runtime is written into the repo. Restart re-reads everything as-is.
(Belt and suspenders: any incidental runtime artifact is also covered by
`.gitignore`.)

Format stability contract:

- The on-disk layout is **plain and tool-readable** — versioned filenames
  (`name.<hash>.<mode>.<flags>.<ts>`) in a mirror of your directory tree. A
  backup is understandable with a file browser, no FFSFS required.
- The config and on-disk formats evolve **additively**: new fields are optional
  and defaulted, so a newer FFSFS reads an older config/datastore without
  reconfiguration. Structural changes go through a versioned migration
  (`config_version`).
- A `.ffsfs-volume.id` file marks each backend volume; keep it. Removable disks
  can be parked cleanly with `backend eject` and brought back with
  `backend attach` (see Storage Backends).

If you use a virtualenv, re-run `pip install -r requirements.txt` after a pull
only when dependencies changed; `setup.sh`/`launch.sh` keep using `./.venv`
automatically.

### Where FFSFS stores things

| What | Location |
|------|----------|
| Realm config (incl. realm secret) | `~/.ffsfs/.storage/<realm>/realm-config.json` |
| Node state (peers, IDs, gossip, subscriptions) | `~/.ffsfs/.storage/` |
| Metadata log | `<storage-base>/.ffsfs-meta.log` |
| File data + all versions | under each backend path, in `.ffsfs_data/` |

The base directory is `~/.ffsfs` by default; override it with `FFSFS_STATE_DIR`.

### Storage footprint — metadata and versions grow

FFSFS is **versioned**: every committed write is kept as a separate version file
next to the logical file, and deletes/moves are recorded as marker versions.
Nothing is overwritten in place. This is what makes history and recovery
possible, but it means:

- Storage use **grows with write history**, not just with current file size. A
  file edited 100 times keeps 100 versions until you prune.
- The append-only metadata log (`.ffsfs-meta.log`) and per-directory data grow
  over time.

For now there is no automatic version pruning/garbage collection — plan disk
capacity accordingly, and prefer roomy backends for write-heavy realms. Use the
dashboard's volume panel to watch free space. Version-retention and pruning
policies are planned future work.

## More Detail

- [agents/operator_guide.md](agents/operator_guide.md): operator workflows,
  backend configuration, VM testing, and recovery.
- [tech_doc.md](tech_doc.md): storage layout, filename schema, peer HTTP API,
  autodiscovery protocol, tunables, and state files.
- [agents/](agents/): project plans and agent coordination notes.
