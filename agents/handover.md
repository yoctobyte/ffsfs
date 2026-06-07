# FFSFS Handover Document (June 2026)

This document serves as the developer handover details for the next agent working on the Flexible Federated Shared File System (FFSFS). 

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
  - `pytest` passed: **137 tests**.
  - `tools/vm/run-two-peer-scenario.sh smoke` passed on 2026-06-07:
    `healthz`, `file-fetch`, `delete-tombstone`, `path-traversal`.

---

## 0. Cycle: Background Sync Workers + Node Roles + Rate-limit Scaffolding

This cycle introduced node-level storage roles, a background sync worker, and
the configuration plumbing for future rate limiting.

- **Node roles** (`ffsvolumes.py`): `access_only`, `cache_limited`,
  `shared_storage`, `superpeer`, `nas_or_fileserver`. Volume-level role
  (`primary`/`archive`/`cache`) is unchanged.
- **Sync policy and worker** (`ffssync.py`):
  - `SyncPolicy.from_config(node_role, sync)` resolves per-realm config and
    role defaults (mode, prefixes, interval, cache_max_bytes).
  - `SyncWorker` runs an active prefix-aware pull (reusing
    `peers.get_newer_or_missing(..., fetch=True)`) and a cache-eviction loop
    that protects the newest version and refuses to evict copies that do not
    provably exist on a peer or another local volume.
  - Worker is started by `FFSFS.__init__` and stopped during `_shutdown`.
- **Rate-limit scaffolding** (`ffsratelimit.py`):
  - `RateLimiter`/`RateLimits` parse config (`disk_fg_bps`, `disk_bg_bps`,
    `net_fg_bps`, `net_bg_bps`; 0 = unlimited). `consume()` is currently a
    no-op — Phase 2 will turn it into a token-bucket and switch the call sites
    flagged with `# TODO(rate-limit)` (in `StorageBackend.commit_temp`,
    `_copy_version_to_volume`, `ffspeers.get_newer_or_missing`,
    `ffspeers.get_file`) to chunked loops.
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

- Real rate-limit enforcement (peer `/get-file` is still a single
  `f.read()` + `make_response(data)`; client side is still
  `f.write(r.content)`). The next cycle should switch to chunked streaming.
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
- **Unit Tests:** 137 tests pass on the workstation in less than 2 seconds
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

### Task A: Rate-limit Enforcement

The config and CLI plumbing exists, but `RateLimiter.consume()` is still a
no-op. Implement token-bucket behavior and wire it into chunked disk/network
I/O at the `# TODO(rate-limit)` sites.

### Task B: Sync Semantics and Status

- Delete/tombstone propagation guarantees and VM coverage.
- Rename and move behavior, especially cross-directory moves.
- Conflict handling for offline concurrent writes.
- `ffsctl` status for pending/failed/stale sync, peer-cache state, and cache
  pressure.

### Task C: Storage Policy Completion

- Media/role-aware write target selection.
- Disk rotation UX around mirror volumes.
- Broader sync policy VM scenarios.

### Task D: Security Hardening (Later MVP/Wider Deployment)

- Peer trust model is prototype-grade (`TRUST_UNKNOWN_PEER = True`).
- Authentication, realm boundaries, and secure sockets should be wired before
  remote/multi-location deployments.

---

## 4. Key Developer Constraints

1. **Safety First:** Do not run FUSE mount tests on the workstation. All FUSE mounting tests must run inside guest VMs using `tools/vm/run-single-vm-smoke.sh` or scenarios.
2. **Git Hygiene:** Do not track `.storage/`, logs, or guest VM overlays. Keep them ignored.
3. **Documentation:** Store all designs, feature plans, and handover docs inside the `agents/` directory rather than local conversation memory.
