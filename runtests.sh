#!/usr/bin/env bash
# runtests.sh — run the FFSFS test suites.
#
# Usage:
#   ./runtests.sh [--unit] [pytest args...]
#
#   (no args)   run ALL tests: compile check + unit tests + disposable-VM smokes
#   --unit      unit tests only (skip the VM smokes)
#   extra args  forwarded to pytest, e.g. ./runtests.sh --unit -k volume -q
#
# VM smokes need QEMU tooling and a base image (tools/vm/build-base-image.sh).
# If those are missing they are reported as SKIPPED, not failed, so the unit
# suite still runs on a box without virtualization.
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

RUN_VM=1
PYTEST_ARGS=()
for a in "$@"; do
    case "$a" in
        --unit|--no-vm) RUN_VM=0 ;;
        --vm) RUN_VM=1 ;;  # accepted; VM already runs by default
        -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
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
    base_image="${FFSFS_VM_BASE_IMAGE:-$SCRIPT_DIR/.vm/images/ubuntu-24.04-server-cloudimg-amd64.qcow2}"
    missing=""
    for c in qemu-system-x86_64 qemu-img cloud-localds ssh rsync curl; do
        command -v "$c" >/dev/null 2>&1 || missing="$missing $c"
    done
    if [ -n "$missing" ]; then
        echo "== VM smokes SKIPPED: missing tools:$missing =="
        echo "   install: sudo apt install -y qemu-system-x86 qemu-utils cloud-image-utils openssh-client rsync curl"
    elif [ ! -f "$base_image" ]; then
        echo "== VM smokes SKIPPED: base image not built =="
        echo "   build once: tools/vm/build-base-image.sh"
    else
        echo "== VM smoke (FUSE + pool + two-peer) =="
        tools/vm/run-single-vm-smoke.sh
        tools/vm/run-single-vm-pool-smoke.sh
        tools/vm/run-two-peer-scenario.sh smoke
    fi
fi

echo "All requested tests passed."
