#!/usr/bin/env bash
# runtests.sh — run the FFSFS test suites.
#
# Usage:
#   ./runtests.sh [--vm] [pytest args...]
#
#   (no args)   compile check + unit tests (fast, safe, no FUSE mount)
#   --vm        also run the disposable-VM smokes (FUSE + two-peer); needs QEMU
#               tooling and a base image (tools/vm/build-base-image.sh)
#   extra args  forwarded to pytest, e.g. ./runtests.sh -k volume -q
#
# Interpreter: FFSFS_PYTHON, else ./.venv, else active $VIRTUAL_ENV, else system
# python3. Tests do NOT need a virtualenv and may be run before ./setup.sh.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

if [ -n "${FFSFS_PYTHON:-}" ]; then
    PYBIN="$FFSFS_PYTHON"
elif [ -x "$SCRIPT_DIR/.venv/bin/python3" ]; then
    PYBIN="$SCRIPT_DIR/.venv/bin/python3"
elif [ -n "${VIRTUAL_ENV:-}" ] && [ -x "$VIRTUAL_ENV/bin/python3" ]; then
    PYBIN="$VIRTUAL_ENV/bin/python3"
else
    PYBIN="python3"
fi

RUN_VM=0
PYTEST_ARGS=()
for a in "$@"; do
    case "$a" in
        --vm) RUN_VM=1 ;;
        -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
        *) PYTEST_ARGS+=("$a") ;;
    esac
done

echo "Using python: $PYBIN"
if ! "$PYBIN" -c "import pytest" >/dev/null 2>&1; then
    echo "error: pytest is not available for $PYBIN" >&2
    echo "  system python:  sudo apt install -y python3-pytest" >&2
    echo "  virtualenv:     pip install -r requirements-dev.txt" >&2
    exit 1
fi

echo "== compile check =="
"$PYBIN" -m py_compile ./*.py

echo "== unit tests =="
"$PYBIN" -m pytest "${PYTEST_ARGS[@]}"

if [ "$RUN_VM" -eq 1 ]; then
    echo "== VM smoke (FUSE + pool + two-peer) =="
    tools/vm/run-single-vm-smoke.sh
    tools/vm/run-single-vm-pool-smoke.sh
    tools/vm/run-two-peer-scenario.sh smoke
fi

echo "All requested tests passed."
