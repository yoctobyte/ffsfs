# FFSFS Handover Document (June 2026)

This document serves as the developer handover details for the next agent working on the Flexible Federated Shared File System (FFSFS). 

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

- **Branch:** `main` (clean and up-to-date with `origin/main`).
- **Unit Tests:** 74 tests pass on the workstation in less than 1.0 second (`pytest`).
- **VM Integration Tests:** 8 scenarios total (6 original + 2 new: `pool-read-write`, `offline-volume`). All individually verified passing. A separate single-VM pool smoke test (`run-single-vm-pool-smoke.sh`) also covers multi-backend pool, `configure.sh`, and `launch.sh` end-to-end.
- **VM test runtime:** The full two-peer scenario suite (`run-two-peer-scenario.sh all`) boots a fresh QEMU VM per scenario. Each run takes 2–5 minutes depending on KVM availability. Budget ~30 minutes for the full suite.

---

## 3. Next Steps (What to Work on Next)

### Task A: Background Catch-Up Sync Worker (Remaining from Multi-Backend)
The pool infrastructure is in place (`ffsvolumes.py`, `ffsctl backend`, pool-aware `StorageBackend`). What remains:
- **Catch-Up Sync:** Implement a background worker that monitors drive mounts. When a previously offline HDD reconnects, scan the metadata log and replicate any files committed in the interim.
- **Disk Rotation:** When swapping HDD1 for HDD2, detect the new drive, identify missing writes, and sync them.
- **Write-Anywhere Fallback:** When the target HDD is offline during commit, write to the primary SSD and record intent for later replication.

### Task B: Background Sync & Storage Roles
- Define storage role profiles (`access_only`, `cache_limited`, `shared_storage`, `superpeer`).
- Eviction policies for cache-limited nodes without deleting local writes.
- Selected-prefix synchronization.

### Task C: Security Hardening (To-Do)
- Peer trust model is prototype-grade (`TRUST_UNKNOWN_PEER = True`).
- LAN-intended usage, but authentication and realm boundaries should be wired in before remote/multi-location deployments.

---

## 4. Key Developer Constraints

1. **Safety First:** Do not run FUSE mount tests on the workstation. All FUSE mounting tests must run inside guest VMs using `tools/vm/run-single-vm-smoke.sh` or scenarios.
2. **Git Hygiene:** Do not track `.storage/`, logs, or guest VM overlays. Keep them ignored.
3. **Documentation:** Store all designs, feature plans, and handover docs inside the `agents/` directory rather than local conversation memory.
