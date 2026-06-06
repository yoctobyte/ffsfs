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
- Support fuller "superpeer" nodes that keep larger or more complete copies.
- Eventually support superpeers with multiple disks, including removable disks
  rotated by a user as a practical backup workflow, such as alternating external
  USB drives.
- Support flexible deployment topologies over time, including remote locations,
  Windows hosts, NAS devices such as Synology, and private overlay networks such
  as Tailscale where appropriate.
- Make different-location backup a core long-term goal, not an afterthought.
- Treat peer federation and storage policy as first-class features, not just
  incidental sync.

This intent should guide design choices, but the immediate priority remains
testing, safety, and correctness.

The exact approach for remote sites, Windows nodes, NAS nodes, and overlay
networking is intentionally not fixed yet. Decide those designs from concrete
hardware and location constraints when they are known.

Security, authentication, and realm boundaries are important architectural
topics, especially for remote and multi-location deployments. For the near-term
testing phase, keep mechanisms simple and explicit. Prefer better configuration
tooling, clear defaults, and test fixtures over a heavy authentication design
before the core behavior is stable.

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

## Phase 6: Scale and Reliability Testing

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

## Phase 7: Feature Work

Goal: add features only after tests can protect current behavior.

Candidate features:

- Better conflict handling.
- Better peer trust/security model.
- Subscriptions/watch behavior.
- Improved CLI for realm lifecycle.
- Recovery tools for orphan temps and meta log inspection.
- Optional lazy listing mode improvements.
- Better status UI or admin commands.

Deliverable:

- Feature work proceeds behind tests and documented behavior.

## Current Priority Queue

1. Add `pytest.ini` and unit tests for `ffsutils.py`.
2. Add storage backend tests.
3. Fix `_commit_delete`.
4. Fix peer `/get-file` path containment.
5. Add peer API tests for the fixed behavior.
6. Build the first single-VM smoke harness.
7. Add two-VM peer sync test.

## Done Criteria for Stabilization

The project is considered stabilized enough for larger feature work when:

- `python3 -m py_compile *.py` passes.
- Unit tests pass on the workstation.
- Single-VM FUSE smoke test passes repeatedly.
- Two-VM peer sync test passes repeatedly.
- Known critical path traversal/delete bugs are fixed.
- README documents install, mount, unmount, and recovery basics.
