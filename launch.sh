#!/usr/bin/env bash
# launch.sh — Launch FFSFS with realm configuration
#
# Usage:
#   ./launch.sh [realm] [--bg] [--allow-inactive]
#
# Reads realm config from ~/.ffsfs/.storage/<realm>/realm-config.json.
# Halts with a clear error if the realm is not configured.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FFSFS="$SCRIPT_DIR/ffsfs.py"
FFSCTL="$SCRIPT_DIR/ffsctl.py"
CONFIG_BASE="$HOME/.ffsfs/.storage"

# Interpreter: explicit override, else project .venv, else active venv, else
# system python3. No .venv present => behaves exactly as before.
resolve_python() {
    if [ -n "${FFSFS_PYTHON:-}" ]; then echo "$FFSFS_PYTHON"; return; fi
    if [ -x "$SCRIPT_DIR/.venv/bin/python3" ]; then echo "$SCRIPT_DIR/.venv/bin/python3"; return; fi
    if [ -n "${VIRTUAL_ENV:-}" ] && [ -x "$VIRTUAL_ENV/bin/python3" ]; then echo "$VIRTUAL_ENV/bin/python3"; return; fi
    echo "python3"
}
PYBIN="$(resolve_python)"

usage() {
    echo "Usage: $0 <realm> [--bg] [--allow-inactive]"
    echo ""
    echo "Launch FFSFS using the realm's stored configuration."
    echo "The realm must be configured first (use setup.sh)."
    echo ""
    echo "Options:"
    echo "  --bg              Run in background mode"
    echo "  --allow-inactive  Launch even if setup has not been activated"
    echo ""
    echo "Examples:"
    echo "  $0 my-realm"
    echo "  $0 my-realm --bg"
    exit 1
}

die() {
    echo "error: $1" >&2
    exit 1
}

REALM=""
BG_FLAG=""
ALLOW_INACTIVE=""

for arg in "$@"; do
    case "$arg" in
        --bg)   BG_FLAG="--bg" ;;
        --allow-inactive) ALLOW_INACTIVE="1" ;;
        --help|-h) usage ;;
        -*)     die "unknown option: $arg" ;;
        *)
            if [ -z "$REALM" ]; then
                REALM="$arg"
            else
                die "unexpected argument: $arg"
            fi
            ;;
    esac
done

# If no realm given, try to find the only configured one
if [ -z "$REALM" ]; then
    if [ ! -d "$CONFIG_BASE" ]; then
        die "no realms configured. Run ./setup.sh to set up a realm."
    fi
    realms=()
    for d in "$CONFIG_BASE"/*/; do
        name="$(basename "$d")"
        if [ -f "$d/realm-config.json" ]; then
            realms+=("$name")
        fi
    done
    if [ ${#realms[@]} -eq 0 ]; then
        die "no realms configured. Run ./setup.sh to set up a realm."
    elif [ ${#realms[@]} -eq 1 ]; then
        REALM="${realms[0]}"
        echo "Using realm: $REALM"
    else
        echo "Multiple realms configured:"
        for r in "${realms[@]}"; do
            echo "  $r"
        done
        die "specify which realm to launch: $0 <realm>"
    fi
fi

CONFIG_FILE="$CONFIG_BASE/$REALM/realm-config.json"

if [ ! -f "$CONFIG_FILE" ]; then
    die "realm '$REALM' is not configured ($CONFIG_FILE not found)."
    echo ""
    echo "Run: ./setup.sh --realm $REALM"
fi

# Validate required fields
validate_field() {
    local key="$1"
    local label="$2"
    local val
    val="$($PYBIN -c "
import json, sys
with open('$CONFIG_FILE') as f:
    d = json.load(f)
v = d.get('$key')
print(v if v else '')
" 2>/dev/null)"
    if [ -z "$val" ]; then
        die "$label not configured for realm '$REALM'. Run: ./setup.sh --realm $REALM"
    fi
    echo "$val"
}

MOUNTPOINT="$(validate_field "mountpoint" "mountpoint")"

# Storage: either storage_pool or base must be set
HAS_POOL="$($PYBIN -c "
import json
with open('$CONFIG_FILE') as f:
    d = json.load(f)
print('yes' if d.get('storage_pool') else '')
" 2>/dev/null)"

HAS_BASE="$($PYBIN -c "
import json
with open('$CONFIG_FILE') as f:
    d = json.load(f)
v = d.get('base') or d.get('storage_base')
print('yes' if v else '')
" 2>/dev/null)"

if [ -z "$HAS_POOL" ] && [ -z "$HAS_BASE" ]; then
    die "no storage configured for realm '$REALM'. Run: ./setup.sh --realm $REALM"
fi

IS_ACTIVE="$($PYBIN -c "
import json
with open('$CONFIG_FILE') as f:
    d = json.load(f)
state = d.get('setup_state') or {}
print('yes' if state.get('activated') or not state else '')
" 2>/dev/null)"

if [ -z "$IS_ACTIVE" ] && [ -z "$ALLOW_INACTIVE" ]; then
    die "realm '$REALM' has not been activated by setup. Run: ./setup.sh --realm $REALM --activate (or pass --allow-inactive)."
fi

# Configured peer port (for the dashboard URL). If busy at startup, FFSFS picks
# the next free port and logs it; this is the configured value.
PORT="$($PYBIN -c "
import json
with open('$CONFIG_FILE') as f:
    d = json.load(f)
print(d.get('port') or '')
" 2>/dev/null)"

# Ensure mountpoint directory exists
if [ ! -d "$MOUNTPOINT" ]; then
    echo "Creating mountpoint directory: $MOUNTPOINT"
    mkdir -p "$MOUNTPOINT"
fi

echo "Launching FFSFS..."
echo "  realm:      $REALM"
echo "  config:     $CONFIG_FILE"
echo "  mountpoint: $MOUNTPOINT"
if [ -n "$PORT" ]; then
    echo "  dashboard:  http://localhost:$PORT/dashboard   (localhost only)"
fi
if [ -n "$BG_FLAG" ]; then
    echo "  mode:       background"
else
    echo "  mode:       foreground"
fi
echo ""

exec "$PYBIN" "$FFSFS" "$MOUNTPOINT" --config "$CONFIG_FILE" $BG_FLAG
