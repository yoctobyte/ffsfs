# CLAUDE.md

Project-specific guidance for Claude-style agents.

## Project Context

FFSFS is an experimental distributed, versioned FUSE filesystem. It stores all
versions next to the logical file under `.ffsfs_data/` while presenting only the
logical tree through FUSE.

The project is prototype-quality. Prefer stabilization, tests, and documentation
over new features until the current priority queue in `AGENTS.md` is done.

## Safety

- Do not run FUSE mount tests on the workstation unless explicitly requested.
- Prefer VM-based tests for FUSE and peer networking.
- Never delete or rewrite user/runtime data unless explicitly requested.
- Treat `.storage/` as local runtime state.
- Keep generated VM images and overlays out of git.

## Coding Preferences

- Follow existing Python style until broader refactoring is justified.
- Add tests before or with correctness fixes.
- Keep edits scoped.
- Use structured path normalization and containment checks for any user-provided
  path.
- Prefer explicit errors/logging in core write/delete/sync paths over silent
  `except Exception: pass`.

## Useful Commands

Local baseline:

```bash
python3 -m py_compile *.py
pytest
```

Import check:

```bash
python3 - <<'PY'
for m in ["crossfuse", "ffsutils", "ffspeers", "ffsautodiscover", "ffsfs"]:
    __import__(m)
    print(m, "OK")
PY
```

Git hygiene:

```bash
git status --short --ignored
git ls-files
```

VM checks:

```bash
tools/vm/run-single-vm-smoke.sh
tools/vm/run-two-peer-scenario.sh file-fetch
```
