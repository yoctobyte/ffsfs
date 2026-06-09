#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Interpreter: explicit override, else project .venv, else active venv, else
# system python3. No .venv present => behaves exactly as before.
if [ -n "${FFSFS_PYTHON:-}" ]; then
    PYBIN="$FFSFS_PYTHON"
elif [ -x "$SCRIPT_DIR/.venv/bin/python3" ]; then
    PYBIN="$SCRIPT_DIR/.venv/bin/python3"
elif [ -n "${VIRTUAL_ENV:-}" ] && [ -x "$VIRTUAL_ENV/bin/python3" ]; then
    PYBIN="$VIRTUAL_ENV/bin/python3"
else
    PYBIN="python3"
fi

exec "$PYBIN" "$SCRIPT_DIR/ffssetup.py" "$@"
