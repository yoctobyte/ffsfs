#!/usr/bin/env bash
# setup.sh — configure/activate an FFSFS realm (console setup app).
#
# After activating a realm, run it with:
#   ./launch.sh <realm>                  # foreground (add --bg for background)
#   ./service.sh install <realm>         # or install as a systemd service
# See service.sh for start/stop/uninstall and the --system (root) option.
#
# Don't remember a realm's dashboard port? Run ./ffsportal.py and open
#   http://127.0.0.1:62965/  — it links to every realm's live dashboard.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Interpreter: explicit override, else project .venv, else active venv, else
# system python3. No .venv present => behaves exactly as before.
resolve_python() {
    if [ -n "${FFSFS_PYTHON:-}" ]; then echo "$FFSFS_PYTHON"; return; fi
    if [ -x "$SCRIPT_DIR/.venv/bin/python3" ]; then echo "$SCRIPT_DIR/.venv/bin/python3"; return; fi
    if [ -n "${VIRTUAL_ENV:-}" ] && [ -x "$VIRTUAL_ENV/bin/python3" ]; then echo "$VIRTUAL_ENV/bin/python3"; return; fi
    echo "python3"
}

# Install requirements into a venv (idempotent) and verify the key imports.
# Returns nonzero if deps are still not importable.
_venv_ensure_deps() {
    local venv="$1"
    echo "Ensuring Python dependencies in .venv ..."
    if ! "$venv/bin/pip" install -q -r "$SCRIPT_DIR/requirements.txt"; then
        echo "warning: pip install failed in the venv." >&2
        return 1
    fi
    if ! "$venv/bin/python3" -c "import flask, requests, fuse" 2>/dev/null; then
        echo "warning: required modules not importable in the venv." >&2
        echo "  If the missing one is 'fuse', the libfuse C library is a SYSTEM" >&2
        echo "  package (not pip): sudo apt install libfuse2t64  (or libfuse2)." >&2
        return 1
    fi
    return 0
}

# Resolve/prepare the Python environment.
# - Honor FFSFS_PYTHON / active $VIRTUAL_ENV as-is.
# - If a project .venv exists, ENSURE its deps are present (this is the common
#   "venv made earlier but empty/partial" trap) — idempotent.
# - Otherwise offer to create one (default yes) on interactive setup.
setup_python_env() {
    [ -n "${FFSFS_PYTHON:-}" ] && return 0
    [ -n "${VIRTUAL_ENV:-}" ] && return 0

    if [ -x "$SCRIPT_DIR/.venv/bin/python3" ]; then
        if ! _venv_ensure_deps "$SCRIPT_DIR/.venv"; then
            echo "  Fix the venv (or remove .venv to use system python3)." >&2
        fi
        return 0
    fi

    [ -t 0 ] || return 0                      # only when interactive
    [ "${FFSFS_NO_VENV:-}" = "1" ] && return 0

    printf "Create a project virtualenv (.venv) for FFSFS? [Y/n]: "
    read -r ans || ans=""
    case "$ans" in
        n|N|no|NO) echo "Using system python3."; return 0 ;;
    esac

    echo "Creating virtualenv at $SCRIPT_DIR/.venv ..."
    if ! python3 -m venv "$SCRIPT_DIR/.venv"; then
        echo "warning: venv creation failed; falling back to system python3." >&2
        echo "  (the venv option needs the 'python3-venv' apt package:" >&2
        echo "     sudo apt install python3-venv)" >&2
        rm -rf "$SCRIPT_DIR/.venv"
        return 0
    fi
    if ! _venv_ensure_deps "$SCRIPT_DIR/.venv"; then
        echo "warning: venv dependency setup incomplete; falling back to system python3." >&2
        rm -rf "$SCRIPT_DIR/.venv"
        return 0
    fi
    echo "Virtualenv ready. setup.sh and launch.sh will use it automatically."
}

setup_python_env
PYBIN="$(resolve_python)"

exec "$PYBIN" "$SCRIPT_DIR/ffssetup.py" "$@"
