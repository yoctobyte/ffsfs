# FFSFS Project Plan

FFSFS already has a useful prototype, but the next work should focus on making
it testable, recoverable, and predictable before adding larger features.

## Product Intent

FFSFS is aiming toward a self-hosted, Linux-oriented file system in the rough
space of "Google Drive, but owned by the user", with local-first behavior and a
persistent storage format that remains understandable outside the software.

Important long-term properties:

- Support multiple independent realms.
- Keep file content verbatim.
- Store enough metadata in filenames that a versioned file can be renamed or
  decoded back to the exact original logical file.
- Preserve a durable, inspectable on-disk structure rather than requiring a hot
  database to understand data.
- Allow nodes to leech/cache selectively: a node may store only locally accessed
  or intentionally cached data, not necessarily the whole realm.
- Support configurable background synchronization so a node can proactively
  pull or keep selected data according to its storage role and availability.
- Default synchronization is pull-based. Peer notifications are hints that new
  versions may exist; they do not force the receiver to sync and do not push
  file bytes into another peer.
- Support fuller redundancy nodes, but do not use `superpeer` as a config role
  because it mixes always-online and huge-storage meanings. These are separate
  axes:
  - Availability: always-online, intermittent, or user-powered on demand.
  - Storage depth: cache-only/limited, normal shared storage, or bulk storage.
- Support sync/storage intent ranging from access-only/cache-only laptops,
  through limited shared storage boxes, to always-on or sometimes-on file
  servers, NAS boxes, and high-capacity replica nodes.
- Eventually support replica/bulk storage with multiple disks, including
  removable disks
  rotated by a user as a practical backup workflow, such as alternating external
  USB drives.
- Support flexible deployment topologies over time, including remote locations,
  Windows hosts, NAS devices such as Synology, and private overlay networks such
  as Tailscale where appropriate.
- Make different-location backup a core long-term goal, not an afterthought.
- Treat peer federation and storage policy as first-class features, not just
  incidental sync.
- Preserve the logical directory structure on every storage backend. Same-
  filesystem moves and renames move the latest version file to the destination
  without byte duplication and record a source `moved` marker as a
  non-authoritative hint carrying the content hash and destination. Cross-device
  moves fall back to copy+source-file removal.
- FFSFS is primarily a single-user/local-first project, not corporate
  NFS/SMB-style concurrent sync. If one user creates conflicting offline
  rename/move operations, manual or later automatic conflict resolution is an
  acceptable consequence of that design.

This intent should guide design choices, but the immediate priority remains
testing, safety, and correctness.

## MVP Scope

Near-term MVP does not require packaging, installers, or a web configuration UI.
Those should come late, after core behavior is stable enough that user-interface
work does not need constant updates for changing semantics.

For now, MVP means a technically comfortable user can check out the latest
GitHub revision, configure a realm with scripts/CLI, and run FFSFS directly on
Linux in a trusted local/LAN environment.

Excluding authentication and secure sockets, the remaining MVP gap is:

- Predictable sync semantics:
  - Delete/tombstone propagation with VM coverage.
  - Conflict handling for offline concurrent rename/move operations.
  - Conflict handling for offline concurrent writes.
  - Recovery from stale peer cache, peer restarts, and interrupted fetches.
  - Failed syncs are expected transient operational states. A failed large
    file, locked file, peer outage, network hiccup, or stale cache must not
    block unrelated files from syncing. Retry later with backoff and expose
    persistent failures to users/operators.
- Operational visibility:
  - `ffsctl` status for active sync, pending replication, failed retries,
    configured peers, and cache pressure.
  - Actionable logs and retry/backoff behavior.
- Storage policy completion:
  - Enforced role/prefix policies beyond the first active-sync prototype.
  - Media/role-aware write target selection.
  - Removable mirror disk rotation workflow.
- Rate limiting:
  - Enforce the existing `RateLimits` config in foreground/background disk and
    network I/O paths.
- At-home redundancy model:
  - It is acceptable for redundancy to be messy and opportunistic.
  - Power-saving matters; workstations and large disk boxes should not need to
    be online 24/7.
  - Peers should be able to remember wanted or temporarily unavailable files
    and catch up when the relevant peer/storage comes online.

Packaging and UI remain important product work, but they are intentionally
deferred until the checkout-and-run MVP is feature-complete.

Web configuration UI direction (next UI milestone):

- Extend the existing Flask peer server with a `/configure` page.
- Read-mostly dashboard: show realm config, peer list, sync status, conflicts,
  storage volumes, and cache pressure.
- Display copyable CLI commands for config mutations rather than implementing
  a full form-based editor. Server restart after config changes is acceptable.
- Access control: localhost is unrestricted; remote access requires a simple
  session password (separate from the realm secret) or HTTP basic-auth.
- Keep it a single-file embedded UI (no JS framework, no build step). Use the
  same minimal inline HTML+CSS pattern as the existing `/status` page.

Web UI status (DONE 2026-06-08):

- `/dashboard` read-only overview: peers, sync status (failed paths, conflicts,
  policy), storage volumes with cached liveness (ONLINE/OFFLINE/STALLED) and
  guarded capacity, plus realm/auth/notify-scope metadata. Renders without ever
  blocking on a stalled volume.
- `/dashboard/config`: applies peer-add live in-process; emits copy-paste
  `ffsctl`/`configure.sh` commands (realm pre-filled) for backend/role/sync/
  ratelimit/realm changes it does not mutate directly.
- Access: HMAC-exempt (a browser cannot sign) and gated to loopback. Remote
  session-password access is the documented follow-up — not yet implemented.
- Open follow-ups: remote session-password auth; richer in-process safe
  mutations; backend-as-resource vs realm-as-logical model with
  detect->suggest->confirm reuse (see below).

NAS deployment strategy (Synology, QNAP, etc.):

- Running FFSFS directly on a NAS appliance is not a near-term goal. DSM/QTS
  environments have limited Python, no FUSE, Docker constraints, and firmware
  updates break custom packages.
- Preferred architecture: a dedicated always-on Linux host (Pi, mini-PC, or
  24/7 server) mounts the NAS share via NFS or SMB, then registers the mount
  as an FFSFS storage backend volume with role `bulk_storage` or `mirror`.
- The NAS is treated as dumb networked storage. No FFSFS software runs on it.
- If the NAS share becomes unavailable (network hiccup, NAS reboot), the
  volume goes OFFLINE automatically. Pending replication catches up when it
  returns. This is already supported by the pool/volume infrastructure.
- A diskless 24/7 server that uses the NAS exclusively for storage is a valid
  deployment: it runs FFSFS as a peer node with `always_online` availability
  and the NAS-backed volume as its primary or sole storage.
- Future: if direct NAS execution becomes desirable (e.g., via Docker on
  Synology), it would run without FUSE (HTTP peer mode only, serving files
  from the NAS filesystem directly). This is a separate design decision.

The exact approach for remote sites, Windows nodes, NAS nodes, and overlay
networking is intentionally not fixed yet. Decide those designs from concrete
hardware and location constraints when they are known.

Security, authentication, and realm boundaries are important. MVP peer security
should use a mandatory per-realm secret with HMAC request signing for any data
exchange. Manual peer approval is optional per node. HTTP remains valid for
trusted LAN performance; HTTPS is optional transport privacy and should not
replace HMAC realm authentication. See `agents/auth_transport_design.md`.

Direct public-IP exposure is explicitly out of scope for the current LAN/overlay
MVP. It needs separate hardening for transport security, per-node identity,
DoS/resource controls, bounded peer sets, public endpoint operations, and
hostile-network testing. See `agents/public_internet_exposure.md`.

Automated testing should use isolated VM networks, not the workstation LAN,
Tailscale, or real remote sites. Real-world deployments are valuable later, but
they are cumbersome and should be configured deliberately by the user for the
actual hardware and location names.

## Principles

- Testing comes first.
- FUSE and peer-network tests run in disposable VMs by default.
- Unit tests must stay fast and safe enough to run on the workstation.
- VM tests use fixed test node names and explicit config files.
- Real-world node names and topology are user configuration, not test defaults.
- Fix correctness and safety issues before scale/performance work.
- Document behavior as it is stabilized, not after the fact.

## Current Status

Completed foundation:

- Local pytest baseline exists with utility, storage, and peer API tests.
- Critical `_commit_delete` and peer `/get-file` containment bugs are fixed and
  covered by tests.
- Single-VM FUSE smoke harness exists and has passed.
- Two-peer VM scenario harness exists with `healthz` and `file-fetch`
  scenarios, and `file-fetch` has passed in real VMs.
- Base VM image and generated run state live under `.vm/` and are ignored by
  git.

Still open before broader feature work:

- Extend storage policy: media/role-aware write target selection, disk
  rotation UX, broader sync policy coverage in VM scenarios.

Completed infrastructure:

- Tiered multi-backend storage pool foundation (`ffsvolumes.py`).
- Volume identifiers (`.ffsfs-volume.id`) and ONLINE/OFFLINE tracking.
- Pool-aware `StorageBackend` with cross-backend read routing.
- Pool-aware write routing, explicit mirror-on-write, pending replication log,
  and periodic catch-up retry for reconnected mirror volumes.
- `ffsctl backend` subcommands (add/remove/list/register).
- `ffsctl realm` subcommands (init/show/set/list) for realm config management.
- `ffsctl role`, `ffsctl sync`, and `ffsctl ratelimit` subcommands.
- Background sync worker (`ffssync.SyncWorker`) with active prefix-aware pull
  and cache-volume eviction.
- Node sync role taxonomy: `access_only`, `cache_limited`,
  `shared_storage`, `replica_storage`, with separate availability/storage
  profile axes.
- Rate-limit enforcement (`ffsratelimit.RateLimits`) with token-bucket
  foreground/background disk/network limits, chunked peer fetch/serve, and
  chunked disk copy.
- Sync review fixes: segment-safe prefix matching, newest-version selection
  across peers, one-shot peer-cache refresh, and wired
  `ffsctl sync <realm> run-once`.
- `launch.sh` and `configure.sh` operator scripts.
- Delete/tombstone propagation (push notifications, active-pull, FUSE visibility).
- True filesystem rename/move with `moved` markers and peer notifications.
- Non-blocking retry with exponential backoff and per-vpath failure tracking.
- `ffsctl sync status` command with live daemon query via `/sync-status` route.
- HMAC peer authentication with per-realm secret.
- Conflict detection: same-hash auto-skip, different-hash conflict recording,
  `.ffsfs-conflicts.json` persistence, virtual `.CONFLICT.<hash8>` FUSE entries,
  user resolution by deleting the unwanted version.

## Phase 1: Test Foundation

Goal: create a reliable safety net around the existing behavior without needing
to mount FUSE on the workstation.

Tasks:

- Add `pytest.ini` with markers:
  - `unit`
  - `vm`
  - `fuse`
  - `network`
  - `two_peer`
  - `destructive`
  - `slow`
- Add unit tests for `ffsutils.py`:
  - `normalize_vpath`
  - `ensure_within_base`
  - `parse_versioned_filename`
  - `build_versioned_filename`
  - Crockford Base32 helpers
  - hash formatting
- Add storage backend tests using `tmp_path`:
  - create temp
  - commit temp
  - pick latest version
  - delete tombstone behavior
  - filenames with multiple dots and subdirectories
- Add peer API tests with Flask test client:
  - realm mismatch
  - `/healthz`
  - `/list-dir`
  - `/head`
  - `/get-file`
  - path traversal rejection
- Add a minimal CI-like local command:

```bash
python3 -m py_compile *.py
pytest
```

Deliverable:

- A fast test suite that exercises core behavior without mounting FUSE.

## Phase 2: Immediate Correctness and Safety Fixes

Goal: fix known bugs and dangerous paths found during the initial review.

Tasks:

- Implement or replace missing `_commit_delete` behavior in `FFSFS.unlink`.
- Add safe path resolution for peer `/get-file` and deprecated fetch endpoint.
- Avoid silent failures in commit, delete, fsync, peer notify, and startup paths
  where the caller needs to know something failed.
- Normalize CLI behavior:
  - remove dead `_depsmain__` block
  - fix `--bg` help text
  - make short/full mode behavior explicit
- Improve configuration ergonomics for testing:
  - make realm, peer port, bind host, storage base, and discovery toggles easy
    to set explicitly
  - document safe local/LAN test defaults
  - avoid hidden behavior that makes VM tests hard to reproduce
  - support simple config files as the base layer for later user tooling
- Make import/dependency behavior explicit and tested:
  - `crossfuse.py` supports both `fuse` and `fusepy`
  - docs list Ubuntu packages

Deliverable:

- Known critical bugs fixed and covered by tests.

## Phase 3: VM Test Harness

Goal: run FUSE and peer tests away from the workstation.

Tasks:

- Create `tools/vm/` scripts:
  - `build-base-image.sh`
  - `run-one-vm.sh`
  - `run-two-vm-test.sh`
  - `collect-logs.sh`
- Build a base Ubuntu/Debian qcow2 image with guest dependencies:
  - `python3`
  - `python3-pytest`
  - `python3-flask`
  - `python3-requests`
  - `python3-fusepy`
  - `libfuse2t64` or `libfuse2`
  - `fuse3`
- Use disposable qcow2 overlays per run.
- Add single-VM smoke tests:
  - import modules
  - mount
  - write/read
  - delete
  - unmount
  - inspect storage layout
- Add failure cleanup:
  - attempt `fusermount3 -u`
  - collect process list, mount table, peer logs, storage tree
  - destroy overlay after success

Deliverable:

- One-command VM smoke test for FUSE behavior.

## Phase 4: Two-Host Peer Testing

Goal: verify peer behavior across isolated hosts.

Tasks:

- Boot two disposable VMs on a private network.
- Support manual peer add before relying on autodiscovery.
- Add two-peer tests:
  - A writes, B fetches
  - A updates, B sees newer version
  - A deletes, B observes tombstone/latest state
  - peer restart
  - stale peer handling
- Add HTTP API contract checks:
  - `/hello`
  - `/status`
  - `/list-files`
  - `/list-dir`
  - `/head`
  - `/get-file`
  - `/notify`
- Add log collection from both VMs.

Deliverable:

- Repeatable two-VM peer sync test.

## Phase 5: Documentation and Operator Workflow

Goal: make the project understandable and recoverable.

Tasks:

- Expand README:
  - install dependencies
  - first mount
  - unmount
  - storage layout warning
  - peer setup
  - troubleshooting
- Add `docs/` or improve existing technical docs:
  - architecture
  - storage format
  - peer protocol
  - VM testing
  - recovery from stuck mount
- Document known limitations:
  - prototype status
  - conflict behavior
  - peer trust model
  - scaling expectations

Deliverable:

- A new user can install, run a scratch realm, unmount, and understand where
  data lives.

## Phase 6: Configuration and Background Sync

Goal: make node roles and synchronization behavior explicit, testable, and
operator-controlled.

This phase should wait until the VM scenarios cover the core peer semantics.
Background sync is the next major feature direction after testing/correctness,
but it needs configuration and policy tests first.

Tasks:

- Add explicit config files or profiles for:
  - realm
  - node name
  - storage base and mountpoint
  - peer port and bind host
  - known peers
  - autodiscovery on/off
  - storage role
  - node availability (`always_online`, `intermittent`, `on_demand`)
  - node storage profile (`cache_only`, `limited`, `bulk_storage`)
  - background sync policy
- Define initial sync roles:
  - `access_only`: browse/fetch on demand, cache local reads only.
  - `cache_limited`: keep a bounded local cache with eviction policy.
  - `shared_storage`: keep selected prefixes available for others.
  - `replica_storage`: actively keep broad or configured replicas for
    redundancy.
- Define peer capability axes:
  - Always-online limited-storage anchor, such as a Pi already running 24/7.
  - On-demand bulk-storage node, such as a workstation or big disk box the user
    powers on when needed.
  - Remote/intermittent backup peer, such as a work-site node once remote sync
    is mature.
- Define background sync policies:
  - disabled
  - selected prefixes
  - whole realm where feasible
  - opportunistic when peers are online
  - scheduled windows for sometimes-online boxes
  - redundancy targets, such as "keep N copies" once peer inventory is reliable
- Add tests before broad implementation:
  - config parsing and defaults
  - policy selection for prefixes
  - two-peer background pull
  - sometimes-offline peer reconnect and catch-up
  - limited-cache behavior without deleting committed local writes

Deliverable:

- A configuration-backed background sync prototype with VM tests proving
  selected-prefix sync, catch-up after offline periods, and role-specific
  storage behavior.

## Phase 7: Scale and Reliability Testing

Goal: learn limits before optimizing.

Tasks:

- Add synthetic data generators:
  - many small files
  - few large files
  - deep directory trees
  - repeated updates to same logical file
- Measure:
  - listing latency
  - latest-version lookup cost
  - peer index refresh cost
  - memory usage
  - mount responsiveness
- Run scale tests only in VMs.
- Record baseline results in docs.

Deliverable:

- Baseline performance profile and known bottlenecks.

## Phase 8: Feature Work

Goal: add features only after tests can protect current behavior.

Candidate features:

- Hardened background synchronization and storage policy, once config and tests
  are in place.
- Better conflict handling.
- Better peer trust/security model.
- Subscriptions/watch behavior.
- Improved CLI for realm lifecycle.
- Recovery tools for orphan temps and meta log inspection.
- Optional lazy listing mode improvements.
- Better status UI or admin commands.
- Packaging/installers and web UI only after checkout-and-run MVP semantics are
  stable.

Deliverable:

- Feature work proceeds behind tests and documented behavior.

## Current Priority Queue

1. Tighten sync semantics and visibility:
   - Delete/tombstone propagation guarantees.
   - Rename and cross-directory move behavior.
   - Conflict handling for offline concurrent writes.
   - Pull-by-default policy: notifications are hints only, not forced sync.
   - Non-blocking retry/status for transient failed syncs.
   - `ffsctl` status for pending/failed/stale sync and peer-cache state.
2. Extend storage policy:
   - Media/role-aware write target selection.
   - Disk rotation UX around mirror volumes.
   - Intent capture DONE 2026-06-08 (enforcement still pending): realm
     `collaboration` (solo|shared, default solo) and per-backend advisory
     hints `device_class` (internal/usb/sd/optical/network), `job`/`job_prefix`,
     with setup assumption defaults (suggest_backend_defaults) and dashboard
     display. Write-routing by job/prefix and "high-prio-small" preference are
     the remaining enforcement work; `max_file_size` from assumptions IS already
     enforced by can_accept_write.
3. Add VM scenarios for cross-directory moves, conflict writes,
   restart-during-fetch, offline disk swap, and broader sync policy coverage.
   - DONE 2026-06-08: `cross-dir-move` (content-hash local move reconstruction,
     no re-download, moved marker at source), `conflict-write` (divergent-hash
     detection + `.ffsfs-conflicts.json` persistence), `restart-during-fetch`
     (source-down clean failure + backoff + recovery, v1 integrity preserved).
     `offline-volume` already existed. Remaining: broader sync-policy coverage.
4. Peer trust/security hardening and secure sockets for wider deployments.
   - Implement realm secret generation/storage.
   - Add HMAC request signing and nonce/timestamp replay checks.
   - Add optional manual peer approval/pending peer state.
   - Add optional HTTPS transport with self-signed cert support.
   - Keep direct public-IP exposure unsupported until the blocker list in
     `agents/public_internet_exposure.md` is addressed.

### Completed in this cycle

- Node sync roles in realm config:
  - `access_only`, `cache_limited`, `shared_storage`, `replica_storage`
    (constants in `ffsvolumes.py`).
  - `node_availability` and `node_storage_profile` are separate config axes.
- Background sync worker (`ffssync.py`):
  - `SyncPolicy` resolves role + per-realm overrides
    (`mode`, `prefixes`, `interval_secs`, `cache_max_bytes`).
  - `SyncWorker` runs an active prefix-aware pull (reusing
    `peers.get_newer_or_missing`) and a cache eviction loop that protects the
    newest version and refuses to delete copies that do not provably exist on
    a peer or other local volume.
- Rate-limit enforcement (`ffsratelimit.py`):
  - `RateLimiter`/`RateLimits` with `from_config` / `to_dict`.
  - Token-bucket blocking in `RateLimiter.consume()`.
  - Foreground/background disk and network buckets are consumed by FUSE
    read/write, commit hashing/copying, mirror copy, peer fetch
    (`iter_content`), and peer `/get-file` streaming.
- New `ffsctl` subcommands: `role`, `sync` (show/set/run-once),
  `ratelimit` (show/set), plus `node_role` validation in `ffsctl realm set`.
- Unit tests:
  - `tests/test_sync_policy.py`, `tests/test_sync_worker.py`,
    `tests/test_ratelimit.py`, `tests/test_role_ctl.py` (140 tests, <2s).
- Review follow-up fixes:
  - Prefix matching is segment-safe (`/share` no longer matches `/shared`).
  - Active sync and peer fetch select the newest known remote version across
    all peers instead of depending on peer iteration order.
  - `ffsctl sync <realm> run-once` configures the peer module, registers the
    backend, loads configured peers, and refreshes peer cache before syncing.
  - `tools/vm/two-peer-common.sh` no longer kills its own SSH reset command
    when stopping prior peer server processes.
- Sync failure policy:
  - Active sync records per-path transient failures in memory.
  - Backoff skips only failed paths; unrelated paths continue syncing.
  - Successful later fetch clears the failure status.
- VM scenarios:
  - `tools/vm/scenarios/two-peer/active-prefix-sync.sh`.
  - `tools/vm/scenarios/two-peer/cache-eviction.sh`.
  - `tools/vm/run-two-peer-scenario.sh smoke` passed on 2026-06-07
    (`healthz`, `file-fetch`, `delete-tombstone`, `path-traversal`).

## Done Criteria for Stabilization

The project is considered stabilized enough for larger feature work when:

- `python3 -m py_compile *.py` passes.
- Unit tests pass on the workstation.
- Single-VM FUSE smoke test passes repeatedly.
- Two-peer VM smoke/all scenario batches pass repeatedly.
- Known critical path traversal/delete bugs are fixed.
- README documents install, mount, unmount, and recovery basics.
