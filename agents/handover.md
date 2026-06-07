# FFSFS Handover Document (June 2026)

This document serves as the developer handover details for the next agent working on the Flexible Federated Shared File System (FFSFS). 

---

## 0.9. Follow-up: Sync Status Tooling

Added `ffsctl sync <realm> status` for operator visibility into sync state.

### Output sections

1. **Sync policy** — node_role, mode (lazy/active), interval, prefixes, cache
   bound.
2. **Peers** — per-peer: tracked file count, last-seen time, cache refresh
   age. Connects to configured peers and refreshes the file cache before
   reporting.
3. **Failed paths** — vpaths with active backoff: attempt count, last error,
   seconds until next retry.
4. **Storage volumes** (when storage pool is configured) — per-volume: role,
   online/offline status, bytes used, cache pressure percentage vs
   `cache_max_bytes`.

### Usage

```
ffsctl sync myrealm status
```

### Implementation

- Added `"status"` to the `sync` subcommand's action choices in `ffsctl.py`.
- The handler wires up `ffspeers` for cache refresh, then constructs a
  `SyncWorker` to access `status()` for failed paths.
- No background process or mount is required — status runs standalone.

### Test coverage (177 tests pass)

- `test_sync_status_shows_policy_and_peers`

---

## 0.8. Follow-up: Tombstone Propagation in Sync

Previously, the sync worker only pulled newer non-delete versions. Remote
tombstones were received into the peer cache but never written locally,
causing deleted files to "resurrect" when a peer reconnected.

### Fix

- `SyncWorker.run_active_once()` now has a two-phase approach:
  1. Fetch newer non-delete versions (as before).
  2. Propagate tombstones: for each vpath where the absolute newest remote
     version is a tombstone newer than the local latest, write a local
     `commit_delete()`.
- Added `_newest_any()` static method that finds the newest version
  regardless of mode (counterpart to `_newest_non_delete()`).
- The tombstone-wins logic correctly handles the case where a peer has both
  `write@100` and `delete@200` — the tombstone wins over the older write.
- Tombstones are only propagated for files that exist locally
  (`local_ts is not None`). Remote deletions of files we never had are
  silently ignored.

### Safety guarantees

- A local write newer than a remote tombstone is NOT overwritten (last-write-
  wins by timestamp).
- A tombstone for a file we never had is not written (avoids polluting
  storage with stale tombstones for files the node never synced).
- `run_active_once()` now returns `tombstones_written` in its result dict.

### Test coverage (176 tests pass)

- `test_active_pull_propagates_remote_tombstone`
- `test_active_pull_skips_tombstone_when_local_is_newer`
- `test_active_pull_skips_tombstone_for_unknown_file`
- `test_active_pull_tombstone_wins_over_older_write`

---

## 0.7. Follow-up: True Move/Rename (No Byte Duplication)

Replaced the previous "copy bytes + tombstone source" rename with a
filesystem-level move that avoids duplicating file content.

### New semantics

- `FFSFS.rename()` calls `StorageBackend.rename_version()` which does an
  `os.rename()` of the latest version file to the destination directory,
  swapping the logical-name prefix in the filename.
- If the rename crosses device boundaries (`EXDEV`), falls back to
  copy+delete (no moved marker at source in that path — uses standard
  `commit_temp` at destination then removes source).
- A `moved` marker is written at the source path via
  `StorageBackend.commit_move_marker()`. Its body contains
  `{"to": "<dest_vpath>"}` for history/recovery tooling. The filename still
  carries the original content hash for correlation.
- No `delete` tombstone is written at the source — the `moved` marker alone
  is sufficient (it is already hidden by `is_hidden_mode()`).
- Old versions stay at the source path. History tools can traverse the
  `moved` marker's body to follow the chain.

### Peer communication

- `notify_move_safe()` sends a `{"event": "move", "vpath": ..., "dest_vpath": ...}`
  to all known peers.
- The `/notify` endpoint handles the `"move"` event by renaming entries in
  the peer's file cache from the old vpath to the new dest_vpath.
- `notify_rename_safe()` is preserved as a thin wrapper around
  `notify_move_safe()` for backward compatibility.

### Sync worker optimization

- Before fetching a file from a peer, the sync worker checks if local
  storage already contains a version with the same content hash at a
  different path (`_try_local_move`). If found, it does a local
  `rename_version` + `commit_move_marker` instead of re-fetching bytes.

### Cross-volume fallback

- When `os.rename()` returns `EXDEV` (different filesystem), the rename
  falls back to copying bytes via `commit_temp` and removing the original
  source file. This is the only case where bytes are duplicated.

### Test coverage (172 tests pass)

- `test_cross_directory_rename_moves_file` — verifies no byte copy, only
  moved marker at source, file readable at destination.
- `test_rename_move_marker_contains_destination` — verifies marker body.
- `test_same_directory_rename` — filename change within same dir.
- `test_rename_notifies_peers_with_move_event` — peer notification.
- Updated `test_rename_error_propagation` and
  `test_peer_notify_errors_ignored` for new call signatures.

---

## 0.6. Follow-up: Authentication and Transport Design

Design conclusion:

- Always require a per-realm secret for peer data exchange.
- Manual peer approval is optional per node.
- Discovery may remain automatic, but discovered peers are only candidates
  until they authenticate.
- HTTP remains supported for trusted LAN performance.
- HTTPS should be an optional transport privacy layer, not the primary trust
  mechanism.
- HMAC request signing with the realm secret is the MVP authentication
  mechanism.
- SSH trust may be useful for bootstrap, but SSH access should not
  automatically imply FFSFS peer trust.

Added `agents/auth_transport_design.md` with:

- expected request headers
- HMAC signing inputs
- reject conditions
- approval modes
- HTTP/HTTPS transport guidance
- SSH bootstrap stance
- future extensions

Easy follow-up tasks for another agent:

- Add `realm_secret` generation in `ffsctl realm init`.
- Store `realm_secret` in `realm-config.json` with restrictive file
  permissions where possible.
- Add a small `ffspeer_auth.py` helper for HMAC signing/verification,
  timestamp checks, and nonce replay cache.
- Add unit tests for HMAC canonicalization and replay rejection.
- Add `peer_trust` config validation with values `realm_secret` and `manual`.
- Add `peer_transport` config validation with values `http` and `https`.
- Add docs to README/operator guide for sharing a realm secret between two
  test nodes.

---

## 0.5. Follow-up: Move/Rename Semantics (SUPERSEDED by 0.7)

> **Note:** Section 0.7 replaces the delete+create semantics below with a true
> filesystem-level rename. The `moved` marker concept is preserved but
> `delete` tombstones are no longer written for moves. Cross-volume moves
> still fall back to copy+delete.

Move/rename design (historical):

- Authoritative behavior is **delete + create**.
- Destination path receives a normal committed `write` version containing the
  latest source bytes.
- Source path receives:
  - a `moved` marker carrying the moved content hash
  - a `delete` tombstone that remains authoritative for visibility
- `moved` is a non-authoritative hint for history/recovery tooling. Correctness
  must not depend on peers understanding `moved`.
- `moved` is treated as delete-like for listings, heads, fetch decisions, and
  local visibility.

Product consequence:

- FFSFS is primarily single-user/local-first, not corporate NFS/SMB-style
  concurrent sync.
- If the same user creates conflicting offline moves/renames on different
  nodes, manual or later automatic resolution is acceptable.
- Because committed versions carry content hashes, a resolver can often locate
  the likely move target by matching the `moved` hash to another path's write
  version.

Implementation in this follow-up:

- Added `mode=moved` support and `is_hidden_mode()` in `ffsutils.py`.
- Updated local/peer/sync visibility logic to treat `moved` as delete-like.
- Changed `FFSFS.rename()` to create destination, record source `moved`, then
  record source `delete`.
- Added unit coverage for cross-directory rename visibility and hash hinting.

---

## 0.4. Follow-up: Superpeer Definition

`superpeer` was ambiguous because it mixed two independent properties:

- Availability: how often the node is reachable.
- Storage depth: how much data it can hold.

New config vocabulary:

- `node_availability`:
  - `always_online`: Pi/NAS/server-style node that is usually reachable, even
    if it has limited storage.
  - `intermittent`: ordinary node that comes and goes.
  - `on_demand`: user-powered workstation/disk box brought online when needed.
- `node_storage_profile`:
  - `cache_only`: only short-lived/on-demand cache.
  - `limited`: bounded local storage.
  - `bulk_storage`: large-capacity storage, possibly offline most of the time.

Important product intent:

- At-home redundancy is allowed to be opportunistic and messy.
- Power-saving matters; large workstations or disk boxes should not need to run
  24/7.
- Always-online limited peers and on-demand bulk peers are both useful, but for
  different reasons.
- Peers should eventually remember wanted or temporarily unavailable files and
  sync them when the relevant peer/storage comes online.
- `superpeer` should not be used as a config role. Pre-stable development does
  not require backward compatibility for ambiguous role names.
- Use `node_role=replica_storage` for broad/configured replica intent, then
  describe actual behavior with `node_availability` and
  `node_storage_profile`.

Implementation in this follow-up:

- Removed `superpeer` and `nas_or_fileserver` from the active node-role
  taxonomy.
- Added `node_role=replica_storage`, plus `node_availability` and
  `node_storage_profile` constants in
  `ffsvolumes.py`.
- `ffsctl realm set` validates both keys.
- `ffsctl role <realm>` shows role, availability, and storage profile.
- Updated roadmap and technical docs with the availability/storage split.

---

## 0.3. Follow-up: Pull Sync + Non-blocking Failures

Sync policy clarification:

- Default synchronization is **pull-based**.
- Peer notifications are hints that new versions may exist. They should not
  force a receiving peer to sync and should not push file bytes into another
  peer.
- Failed sync attempts are normal operational states, not immediate fatal
  errors. Causes may include large files, locked files, peer outages, network
  hiccups, stale cache, or temporary permissions.
- A failed path must not block unrelated files from syncing.

Implementation in this follow-up:

- `SyncWorker` tracks transient active-pull failures per logical path in
  memory.
- Failures use exponential backoff per path. During backoff the worker skips
  only that path and continues syncing other eligible paths.
- Successful later fetch clears the path failure.
- `SyncWorker.status()` reports policy, thread state, and failed paths.
- `ffsctl sync <realm> run-once` prints failed-path status when present.

Future work:

- Persist or summarize failure history for mounted services.
- Add richer `ffsctl sync/status` output for pending, backing off, stale peer
  cache, and permanent-looking failures.

---

## 0.2. Follow-up: Rate-limit Enforcement

Rate-limit config is no longer scaffolding-only.

- **Token bucket** (`ffsratelimit.py`):
  - `RateLimiter.consume()` now blocks when `bytes_per_sec > 0`.
  - `0` remains unlimited.
  - Tests use injected clock/sleeper hooks so the suite stays fast.
- **Filesystem disk limits** (`ffsfs.py`):
  - `StorageBackend` accepts `RateLimits`.
  - Foreground disk limits are consumed during FUSE read/write and commit-time
    temp hashing/cross-volume commit copy.
  - Background disk limits are consumed during mirror/pending-replication
    copies.
- **Peer network limits** (`ffspeers.py`):
  - `/get-file` uses a streamed `Response` and consumes foreground disk and
    network limits per chunk.
  - `get_newer_or_missing(..., fetch=True)` uses `requests.iter_content()`
    and consumes background network and disk limits per chunk.
  - `set_rate_limits()` lets the mounted filesystem and CLI sync path wire the
    configured limits into the peer module.
- **CLI wiring** (`ffsctl.py`):
  - `ffsctl sync <realm> run-once` now builds `RateLimits` from config and
    passes them to the backend, peer module, and sync worker.
- **Verification**:
  - `python3 -m py_compile *.py` passed.
  - `pytest` passed: **140 tests**.

---

## 0.1. Follow-up: Sync Review Fixes + MVP Scope

After reviewing the sync implementation, this follow-up fixed the highest-risk
behavioral gaps and clarified the MVP target.

- **MVP scope decision**:
  - Packaging/installers and a web configuration UI are deferred until the
    checkout-and-run GitHub workflow is feature-complete.
  - Near-term MVP assumes Linux users can clone/update from GitHub, configure
    with scripts/CLI, and run directly.
  - Authentication and secure sockets remain important, but the next blockers
    are rate limiting, sync semantics, storage policy, and operational status.
- **Storage-layout intention**:
  - Every storage backend should mimic the logical folder structure for normal
    committed versions, updates, deletes/tombstones, and same-directory
    renames.
  - Cross-directory moves are the special case requiring explicit behavior,
    tests, and documentation.
- **Sync fixes**:
  - Prefix matching is segment-safe (`/share` no longer matches `/shared`).
  - `SyncWorker.run_active_once()` aggregates the newest remote version per
    logical path across all peers before deciding whether to fetch.
  - `ffspeers.get_newer_or_missing()` fetches the newest known peer version
    across all peers, rather than whichever peer appears first.
  - `ffsctl sync <realm> run-once` now sets the peer realm, registers the
    backend, loads configured peers, and forces a one-shot peer-cache refresh.
  - Added `ffspeers.refresh_peer_filecache_once(force=False)` for CLI and VM
    use.
- **VM harness fix**:
  - `tools/vm/two-peer-common.sh` now uses self-safe `pkill` patterns when
    stopping peer server processes, avoiding accidental termination of the SSH
    reset command.
- **Verification**:
  - `python3 -m py_compile *.py` passed.
  - `pytest` passed: **137 tests** at that checkpoint.
  - `tools/vm/run-two-peer-scenario.sh smoke` passed on 2026-06-07:
    `healthz`, `file-fetch`, `delete-tombstone`, `path-traversal`.

---

## 0. Cycle: Background Sync Workers + Node Roles + Rate-limit Scaffolding

This cycle introduced node-level storage roles, a background sync worker, and
the configuration plumbing for future rate limiting.

- **Node roles** (`ffsvolumes.py`): `access_only`, `cache_limited`,
  `shared_storage`, `replica_storage`. Availability and storage depth are
  separate config axes. Volume-level role (`primary`/`archive`/`cache`) is
  unchanged.
- **Sync policy and worker** (`ffssync.py`):
  - `SyncPolicy.from_config(node_role, sync)` resolves per-realm config and
    role defaults (mode, prefixes, interval, cache_max_bytes).
  - `SyncWorker` runs an active prefix-aware pull (reusing
    `peers.get_newer_or_missing(..., fetch=True)`) and a cache-eviction loop
    that protects the newest version and refuses to evict copies that do not
    provably exist on a peer or another local volume.
  - Worker is started by `FFSFS.__init__` and stopped during `_shutdown`.
- **Rate-limit plumbing** (`ffsratelimit.py`):
  - `RateLimiter`/`RateLimits` parse config (`disk_fg_bps`, `disk_bg_bps`,
    `net_fg_bps`, `net_bg_bps`; 0 = unlimited). Follow-up 0.2 implemented
    token-bucket enforcement and chunked I/O at the relevant disk/peer paths.
- **CLI** (`ffsctl.py`): new `role`, `sync`, and `ratelimit` subcommands.
  `ffsctl realm set node_role <r>` validates against `NODE_ROLES`.
  `ffsctl sync <realm> run-once` is useful for VM scenarios — it builds a
  backend without mounting FUSE and triggers one active pull + one eviction
  pass.
- **Config schema** (`realm-config.json`): new optional keys `node_role`,
  `sync` (object), `rate_limits` (object). All have safe defaults.
- **Tests**: `tests/test_sync_policy.py`, `tests/test_sync_worker.py`,
  `tests/test_ratelimit.py`, `tests/test_role_ctl.py`. Total **137 unit tests
  pass in <2s**.
- **VM scenarios** added under `tools/vm/scenarios/two-peer/`:
  - `active-prefix-sync.sh` — A is primary writer; B (shared_storage with
    prefix `/share/`) runs `SyncWorker.run_active_once` and pulls only the
    `/share/` file, leaving `/private/` alone.
  - `cache-eviction.sh` — A has primary + cache volumes; old version sits on
    cache, newer on primary, peer cache says peer has the old version too,
    eviction removes it while protecting the newest version.

### What is intentionally not done

- Per-volume sync override (the `volume.sync` field is reserved but not
  honored).
- Disk rotation UX changes — existing pending-replication catch-up still
  handles the basic re-attach case.

---

## 1. What was Completed & Pushed

We have finished the FUSE write durability improvements, configuration normalization, and documentation expansion phases, completing items 1 through 6 of the stabilization roadmap:

1. **Durability & Silent Failure Reductions:**
   - Write, flush, fsync, commit, and rename exceptions are no longer swallowed in [ffsfs.py](file:///home/rene/ffsfs/ffsfs.py) and now bubble up to FUSE and the calling application.
   - Resource cleanup (closing handles, removing entries from `fh_map`) is wrapped in try-finally blocks to prevent descriptor leaks under failed writes.
   - Peer notification failures are caught and logged as warnings (`[ffsfs] peer notify failed: ...`) to ensure local operations remain offline-tolerant.
   - Unit tests covering failure propagation and cleanup were added to `tests/test_error_propagation.py`.

2. **CLI & Configuration Normalization:**
   - Implemented dynamic JSON configuration file loading (`--config <path>`).
   - Precedence order: Command Line Args > Config File > Environment Variables > Defaults.
   - Support configuration for `realm`, `base`, `mountpoint`, `port`, `bind_host`, `node_name` / `hostname`, `autodiscover`, and `known_peers`.
   - Fixed Flask bind IP address hardcoding in [ffspeers.py](file:///home/rene/ffsfs/ffspeers.py) to bind to a customizable `PEER_BIND_HOST`.
   - Cleaned up dead `_depsmain__` block and corrected `--bg` help description.
   - Added configuration loading unit tests to `tests/test_config.py`.

3. **VM Integration Testing:**
   - Created four new two-peer VM scenarios: `update-newer-version.sh`, `path-traversal.sh`, `peer-restart.sh`, and `delete-tombstone.sh`.
   - Enhanced `run-two-peer-scenario.sh` to support the `all` runner target, timeouts, and log folder summaries.
   - Ran all 6 VM scenarios; they are verified passing.

4. **Operator Guide:**
   - Wrote [agents/operator_guide.md](file:///home/rene/ffsfs/agents/operator_guide.md), detailing configurations, CLI tools, directory structure, schemas, VM testing, recovery from stuck mounts, and known limits.

5. **Multi-Backend Storage Pool & Configuration Tooling:**
   - Created [ffsvolumes.py](file:///home/rene/ffsfs/ffsvolumes.py) with `Volume` and `StoragePool` classes: volume ID files (`.ffsfs-volume.id`), ONLINE/OFFLINE status tracking, write-target routing, cross-backend read scanning.
   - Modified `StorageBackend` in [ffsfs.py](file:///home/rene/ffsfs/ffsfs.py) to accept an optional `StoragePool`; `pick_latest()` scans all online backends for the newest version.
   - Extended config schema with `storage_pool` key in `--config` JSON, parsed and wired through `mount()` in [ffsfs.py](file:///home/rene/ffsfs/ffsfs.py).
   - Added `ffsctl backend` subcommands (add/remove/list/register) and `ffsctl realm` subcommands (init/show/set/list) in [ffsctl.py](file:///home/rene/ffsfs/ffsctl.py).
   - Created `launch.sh` (config-aware launcher that halts when unconfigured) and `configure.sh` (interactive configuration wrapper).
   - Added 38 new unit tests across `test_volumes.py`, `test_pool_backend.py`, `test_backend_ctl.py`, and `test_config.py` (74 total, all passing).

---

## 2. Current State of the Codebase

- **Branch:** `main`.
- **Unit Tests:** 140 tests pass on the workstation in less than 2 seconds
  (`pytest`).
- **VM Integration Tests:** Two-peer VM scenario harness supports `smoke` and
  `all` batches in one VM boot. The latest verified smoke batch passed 4
  scenarios: `healthz`, `file-fetch`, `delete-tombstone`, `path-traversal`.
  A separate single-VM pool smoke test (`run-single-vm-pool-smoke.sh`) also
  covers multi-backend pool, `configure.sh`, and `launch.sh` end-to-end.
- **VM test runtime:** `run-two-peer-scenario.sh smoke` reuses one QEMU VM for
  the fast peer batch. `run-two-peer-scenario.sh all` runs all two-peer
  scenarios in one VM boot and should be used before larger sync/storage
  changes are considered done.

---

## 3. Next Steps (What to Work on Next)

### Task A: Sync Semantics and Status

- Delete/tombstone propagation guarantees and VM coverage.
- Rename and move behavior, especially cross-directory moves.
- Conflict handling for offline concurrent writes.
- `ffsctl` status for pending/failed/stale sync, peer-cache state, and cache
  pressure.

### Task B: Storage Policy Completion

- Media/role-aware write target selection.
- Disk rotation UX around mirror volumes.
- Broader sync policy VM scenarios.

### Task C: Security Hardening (Later MVP/Wider Deployment)

- Peer trust model is still prototype-grade, but unknown peers are not
  auto-added by default; `ffsctl peer` manages `known_peers` and
  `approved_peers`.
- Authentication, realm boundaries, and secure sockets should be wired before
  remote/multi-location deployments.

---

## 4. Key Developer Constraints

1. **Safety First:** Do not run FUSE mount tests on the workstation. All FUSE mounting tests must run inside guest VMs using `tools/vm/run-single-vm-smoke.sh` or scenarios.
2. **Git Hygiene:** Do not track `.storage/`, logs, or guest VM overlays. Keep them ignored.
3. **Documentation:** Store all designs, feature plans, and handover docs inside the `agents/` directory rather than local conversation memory.
