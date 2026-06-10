#!/usr/bin/env bash
# service.sh — install/manage an FFSFS realm as a systemd service.
#
# FFSFS is LAN/overlay-only. Do NOT expose it to the public internet.
#
# Usage:
#   ./service.sh install   <realm> [--system]
#   ./service.sh uninstall <realm> [--system]
#   ./service.sh start      <realm> [--system]
#   ./service.sh stop       <realm> [--system]
#   ./service.sh restart    <realm> [--system]
#   ./service.sh status     <realm> [--system]
#
# Default is a *user* service (systemctl --user): no root, runs as you, starts
# on login. Pass --system for a root-owned system service (NOT recommended yet —
# see the warning printed at install time).
#
# A single systemd template unit "ffsfs@.service" is installed; each realm is an
# instance "ffsfs@<realm>". Realms must be configured + activated first
# (./setup.sh --realm <realm> --activate).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LAUNCH="$SCRIPT_DIR/launch.sh"
SELF="$SCRIPT_DIR/service.sh"
CONFIG_BASE="$HOME/.ffsfs/.storage"
UNIT_NAME="ffsfs@.service"

die() { echo "error: $1" >&2; exit 1; }

usage() {
    sed -n '2,30p' "$SELF" | sed 's/^# \{0,1\}//'
    exit 1
}

# ---- argument parsing -------------------------------------------------------
[ $# -ge 1 ] || usage
ACTION="$1"; shift || true

REALM=""
SYSTEM=0
for arg in "$@"; do
    case "$arg" in
        --system) SYSTEM=1 ;;
        --help|-h) usage ;;
        -*) die "unknown option: $arg" ;;
        *)
            if [ -z "$REALM" ]; then REALM="$arg"
            else die "unexpected argument: $arg"; fi
            ;;
    esac
done

# ---- systemctl wrapper (user vs system) -------------------------------------
if [ "$SYSTEM" -eq 1 ]; then
    UNIT_DIR="/etc/systemd/system"
    WANTED_BY="multi-user.target"
    SC() { systemctl "$@"; }
    if [ "$(id -u)" -ne 0 ]; then
        die "--system requires root. Re-run with sudo, or drop --system for a user service."
    fi
else
    UNIT_DIR="$HOME/.config/systemd/user"
    WANTED_BY="default.target"
    SC() { systemctl --user "$@"; }
fi

INSTANCE="ffsfs@${REALM}"
UNIT_PATH="$UNIT_DIR/$UNIT_NAME"

require_realm() {
    [ -n "$REALM" ] || die "realm name required: $0 $ACTION <realm> [--system]"
}

# Internal helper invoked by the unit's ExecStopPost: force-unmount the realm's
# mountpoint in case the FUSE process did not unmount cleanly on stop.
if [ "$ACTION" = "__umount" ]; then
    require_realm
    cfg="$CONFIG_BASE/$REALM/realm-config.json"
    [ -f "$cfg" ] || exit 0
    mp="$(python3 -c "import json,sys
try:
    print(json.load(open('$cfg')).get('mountpoint',''))
except Exception:
    pass" 2>/dev/null || true)"
    [ -n "$mp" ] || exit 0
    if mountpoint -q "$mp" 2>/dev/null; then
        fusermount -u "$mp" 2>/dev/null || fusermount3 -u "$mp" 2>/dev/null \
            || umount "$mp" 2>/dev/null || true
    fi
    exit 0
fi

write_unit() {
    mkdir -p "$UNIT_DIR"
    cat > "$UNIT_PATH" <<EOF
[Unit]
Description=FFSFS realm %i (versioned FUSE filesystem, LAN-only)
Documentation=file://$SCRIPT_DIR/agents/CLAUDE.md
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$SCRIPT_DIR
ExecStart=$LAUNCH %i
# Stop with SIGINT so FFSFS takes its clean Ctrl-C unmount path; fall back to a
# forced unmount if the process leaves a stale FUSE mount behind.
KillSignal=SIGINT
ExecStopPost=$SELF __umount %i
TimeoutStopSec=20
Restart=on-failure
RestartSec=5

[Install]
WantedBy=$WANTED_BY
EOF
    echo "Wrote unit: $UNIT_PATH"
}

case "$ACTION" in
    install)
        require_realm
        cfg="$CONFIG_BASE/$REALM/realm-config.json"
        [ -f "$cfg" ] || die "realm '$REALM' is not configured ($cfg not found). Run: ./setup.sh --realm $REALM"

        if [ "$SYSTEM" -eq 1 ]; then
            echo "============================================================"
            echo "WARNING: system service (root) is NOT recommended yet."
            echo "  - FUSE filesystem will run as root."
            echo "  - It reads realm config from /root/.ffsfs, not your user."
            echo "  - FFSFS is LAN-only; never expose it to the internet."
            echo "Prefer a user service (drop --system). Continuing in 5s; Ctrl-C to abort."
            echo "============================================================"
            sleep 5
        fi

        write_unit
        SC daemon-reload
        SC enable "$INSTANCE"
        echo "Enabled $INSTANCE."
        if [ "$SYSTEM" -eq 0 ]; then
            echo "Tip: 'loginctl enable-linger $USER' to keep it running without an active login."
        fi
        if [ "$SYSTEM" -eq 1 ]; then
            echo "Start now with: $0 start $REALM --system"
        else
            echo "Start now with: $0 start $REALM"
        fi
        ;;
    uninstall)
        require_realm
        SC disable "$INSTANCE" 2>/dev/null || true
        SC stop "$INSTANCE" 2>/dev/null || true
        # Only remove the shared template unit if no other realm instance is enabled.
        others="$(SC list-unit-files 'ffsfs@*' 2>/dev/null | grep -c enabled || true)"
        if [ "${others:-0}" -le 0 ]; then
            rm -f "$UNIT_PATH" && echo "Removed unit: $UNIT_PATH"
        else
            echo "Kept shared unit ($UNIT_PATH); other ffsfs@ instances still enabled."
        fi
        SC daemon-reload
        echo "Uninstalled $INSTANCE."
        ;;
    start)   require_realm; SC start   "$INSTANCE"; SC --no-pager status "$INSTANCE" || true ;;
    stop)    require_realm; SC stop    "$INSTANCE" ;;
    restart) require_realm; SC restart "$INSTANCE" ;;
    status)  require_realm; SC --no-pager status "$INSTANCE" ;;
    *) usage ;;
esac
