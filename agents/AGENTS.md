# FFSFS Agent Guide

This directory contains coordination docs for automated and human agents working
on FFSFS.

## Start Here

Read these files before changing behavior:

- `project_plan.md`: stabilization roadmap and current priority queue.
- `vm_testing_plan.md`: VM-first strategy for FUSE and peer-network tests.
- `../readme.MD`: user-facing install and quick-start notes.
- `../tech_doc.md`: storage layout, peer API, discovery, and tunables.

## Current Priorities

1. Add `pytest.ini` and unit tests for `ffsutils.py`.
2. Add storage backend tests.
3. Fix `_commit_delete`.
4. Fix peer `/get-file` path containment.
5. Add peer API tests for the fixed behavior.
6. Build the first single-VM smoke harness.
7. Add two-VM peer sync test.

## Working Rules

- Keep workstation-hostile tests out of normal local runs.
- Run FUSE and peer-network tests in disposable VMs by default.
- Keep changes small and covered by tests where practical.
- Do not commit `.storage/`, `__pycache__/`, VM images, logs, or local env files.
- Avoid broad restructuring until the test foundation exists.
- Preserve the vdir-preserving storage model unless explicitly changing the
  format with tests and migration notes.

## Known Risks

- `FFSFS.unlink` currently calls missing `_commit_delete`.
- Peer `/get-file` path containment needs hardening.
- FUSE mount behavior should be validated only inside VMs.
- Peer trust/security model is prototype-grade.
- There is no real test suite yet.

## Verification Baseline

Use this as the minimal non-FUSE check:

```bash
python3 -m py_compile *.py
```

After tests are added, the baseline should become:

```bash
python3 -m py_compile *.py
pytest
```
