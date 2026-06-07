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

---

## 2. Current State of the Codebase

- **Branch:** `main` (clean and up-to-date with `origin/main`).
- **Unit Tests:** 36 tests pass on the workstation in less than 1.0 second (`pytest`).
- **VM Integration Tests:** 6 scenarios pass successfully in disposable VMs (`tools/vm/run-two-peer-scenario.sh all`).

---

## 3. Next Steps (What to Work on Next)

We are now ready for Phase 6 of the project: **Multi-Backend Tiered Storage Pool** and **Background Synchronization**.

### Task A: Tiered Storage Backends (Refer to [agents/multi_backend_design.md](file:///home/rene/ffsfs/agents/multi_backend_design.md))
- **Volume Tracking:** Write a volume ID file `.ffsfs-volume.id` on each configured backend path.
- **Offline Tolerance:** Modify `StorageBackend` to verify `.ffsfs-volume.id` on read/write. If missing or unreadable, mark that backend as `OFFLINE`.
- **Staging / Write-Anywhere:** When a backend is `OFFLINE`, write commits to the primary SSD backend.
- **Catch-Up Sync:** Implement a background worker that replicates committed files from SSD to the offline backend once it becomes `ONLINE` again.
- **CLI Commands:** Add subcommands under `ffsctl.py` to add, remove, and list backend paths and volumes.

### Task B: Background Sync & Storage Roles
- Define storage role profiles (`access_only`, `cache_limited`, `shared_storage`, `superpeer`).
- Eviction policies for cache-limited nodes without deleting local writes.
- Selected-prefix synchronizations.

---

## 4. Key Developer Constraints

1. **Safety First:** Do not run FUSE mount tests on the workstation. All FUSE mounting tests must run inside guest VMs using `tools/vm/run-single-vm-smoke.sh` or scenarios.
2. **Git Hygiene:** Do not track `.storage/`, logs, or guest VM overlays. Keep them ignored.
3. **Documentation:** Store all designs, feature plans, and handover docs inside the `agents/` directory rather than local conversation memory.
