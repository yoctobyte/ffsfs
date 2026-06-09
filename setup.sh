#!/usr/bin/env bash
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

# Offer to create a project virtualenv on first interactive setup. Default yes:
# it isolates and pins the pip deps (flask/requests/fusepy) and makes future
# "git pull + restart" upgrades cleaner. Skipped if a venv/override is already
# in play, if non-interactive, or if the user opts out.
maybe_offer_venv() {
    [ -n "${FFSFS_PYTHON:-}" ] && return 0
    [ -n "${VIRTUAL_ENV:-}" ] && return 0
    [ -x "$SCRIPT_DIR/.venv/bin/python3" ] && return 0
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
        rm -rf "$SCRIPT_DIR/.venv"
        return 0
    fi
    echo "Installing dependencies (flask, requests, fusepy) ..."
    if ! "$SCRIPT_DIR/.venv/bin/pip" install -q -r "$SCRIPT_DIR/requirements.txt"; then
        echo "warning: pip install failed; falling back to system python3." >&2
        echo "  (the FUSE C library still comes from system packages: libfuse2t64/libfuse2)" >&2
        rm -rf "$SCRIPT_DIR/.venv"
        return 0
    fi
    echo "Virtualenv ready. setup.sh and launch.sh will use it automatically."
}

maybe_offer_venv
PYBIN="$(resolve_python)"

exec "$PYBIN" "$SCRIPT_DIR/ffssetup.py" "$@"
