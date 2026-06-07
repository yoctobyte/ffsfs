#!/usr/bin/env bash
# configure.sh — FFSFS configuration tool
#
# Interactive configuration wrapper for FFSFS realms.
# Wraps ffsctl.py commands with a user-friendly interface.
#
# Usage:
#   ./configure.sh                    # interactive menu
#   ./configure.sh <command> [args]   # direct command
#
# Commands:
#   init <realm> [--mountpoint <path>] [--base <path>]
#   show <realm>
#   list
#   set <realm> <key> <value>
#   set-mountpoint <realm> <path>
#   set-base <realm> <path>
#   set-node-name <realm> <name>
#   set-port <realm> <port>
#   add-peer <realm> <host:port>
#   remove-peer <realm> <host:port>
#   list-peers
#   add-backend <realm> <path> [--role <role>] [--id <label>]
#   remove-backend <realm> <id_or_path>
#   list-backends <realm>

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FFSCTL="$SCRIPT_DIR/ffsctl.py"
CONFIG_BASE="$HOME/.ffsfs/.storage"

usage() {
    echo "FFSFS Configuration Tool"
    echo ""
    echo "Usage:"
    echo "  $0                    Interactive menu"
    echo "  $0 <command> [args]   Direct command"
    echo ""
    echo "Commands:"
    echo "  init <realm> [--mountpoint <path>] [--base <path>]"
    echo "  show <realm>                        Show realm config"
    echo "  list                                List configured realms"
    echo "  set <realm> <key> <value>           Set a config value"
    echo "  set-mountpoint <realm> <path>       Set mountpoint"
    echo "  set-base <realm> <path>             Set storage base"
    echo "  set-node-name <realm> <name>        Set node name"
    echo "  set-port <realm> <port>             Set peer port"
    echo "  add-peer <realm> <host:port>        Add known peer"
    echo "  remove-peer <realm> <host:port>     Remove known peer"
    echo "  list-peers                          List known peers"
    echo "  add-backend <realm> <path>          Add storage backend"
    echo "      [--role <archive|cache>] [--id <label>]"
    echo "  remove-backend <realm> <id_or_path> Remove storage backend"
    echo "  list-backends <realm>               List storage backends"
    echo ""
    echo "Config keys: mountpoint, base, port, bind_host, node_name,"
    echo "             autodiscover, known_peers"
    exit 0
}

die() {
    echo "error: $1" >&2
    exit 1
}

require_arg() {
    if [ -z "${1:-}" ]; then
        die "$2"
    fi
}

# ---- direct command handlers ----

cmd_init() {
    local realm="${1:-}"
    shift || true
    require_arg "$realm" "realm name required"
    local extra_args=()
    while [ $# -gt 0 ]; do
        case "$1" in
            --mountpoint) extra_args+=("--mountpoint" "$2"); shift 2 ;;
            --base)       extra_args+=("--base" "$2"); shift 2 ;;
            *)            die "unknown option for init: $1" ;;
        esac
    done
    python3 "$FFSCTL" realm init "$realm" "${extra_args[@]}"
}

cmd_show() {
    local realm="${1:-}"
    require_arg "$realm" "realm name required"
    python3 "$FFSCTL" realm show "$realm"
}

cmd_list_realms() {
    python3 "$FFSCTL" realm list
}

cmd_set() {
    local realm="${1:-}" key="${2:-}" value="${3:-}"
    require_arg "$realm" "realm name required"
    require_arg "$key" "config key required"
    require_arg "$value" "config value required"
    python3 "$FFSCTL" realm set "$realm" "$key" "$value"
}

cmd_set_mountpoint() {
    local realm="${1:-}" path="${2:-}"
    require_arg "$realm" "realm name required"
    require_arg "$path" "mountpoint path required"
    python3 "$FFSCTL" realm set "$realm" mountpoint "$(realpath -m "$path")"
}

cmd_set_base() {
    local realm="${1:-}" path="${2:-}"
    require_arg "$realm" "realm name required"
    require_arg "$path" "storage base path required"
    python3 "$FFSCTL" realm set "$realm" base "$(realpath -m "$path")"
}

cmd_set_node_name() {
    local realm="${1:-}" name="${2:-}"
    require_arg "$realm" "realm name required"
    require_arg "$name" "node name required"
    python3 "$FFSCTL" realm set "$realm" node_name "$name"
}

cmd_set_port() {
    local realm="${1:-}" port="${2:-}"
    require_arg "$realm" "realm name required"
    require_arg "$port" "port number required"
    python3 "$FFSCTL" realm set "$realm" port "$port"
}

cmd_add_peer() {
    local realm="${1:-}" peer="${2:-}"
    require_arg "$realm" "realm name required"
    require_arg "$peer" "peer address required (host:port)"
    # Store in realm config as known_peers array
    local cfg="$CONFIG_BASE/$realm/realm-config.json"
    if [ ! -f "$cfg" ]; then
        die "realm '$realm' not configured. Run: $0 init $realm"
    fi
    python3 -c "
import json
with open('$cfg') as f:
    d = json.load(f)
peers = d.get('known_peers', [])
peer = '$peer'
if peer not in peers:
    peers.append(peer)
    d['known_peers'] = peers
    with open('$cfg', 'w') as f:
        json.dump(d, f, indent=2)
        f.write('\n')
    print(f'Added peer: {peer}')
else:
    print(f'Peer already present: {peer}')
"
}

cmd_remove_peer() {
    local realm="${1:-}" peer="${2:-}"
    require_arg "$realm" "realm name required"
    require_arg "$peer" "peer address required (host:port)"
    local cfg="$CONFIG_BASE/$realm/realm-config.json"
    if [ ! -f "$cfg" ]; then
        die "realm '$realm' not configured."
    fi
    python3 -c "
import json
with open('$cfg') as f:
    d = json.load(f)
peers = d.get('known_peers', [])
peer = '$peer'
if peer in peers:
    peers.remove(peer)
    d['known_peers'] = peers
    with open('$cfg', 'w') as f:
        json.dump(d, f, indent=2)
        f.write('\n')
    print(f'Removed peer: {peer}')
else:
    print(f'Peer not found: {peer}')
"
}

cmd_list_peers() {
    echo "Known peers (peers.conf):"
    python3 "$FFSCTL" peers list
    echo ""
    echo "Known peers (realm configs):"
    if [ -d "$CONFIG_BASE" ]; then
        for d in "$CONFIG_BASE"/*/; do
            realm="$(basename "$d")"
            cfg="$d/realm-config.json"
            if [ -f "$cfg" ]; then
                python3 -c "
import json
with open('$cfg') as f:
    d = json.load(f)
peers = d.get('known_peers', [])
if peers:
    print(f'  [{realm}]')
    for p in peers:
        print(f'    {p}')
"
            fi
        done
    fi
}

cmd_add_backend() {
    local realm="${1:-}" path="${2:-}"
    shift 2 || true
    require_arg "$realm" "realm name required"
    require_arg "$path" "backend path required"
    python3 "$FFSCTL" backend add "$realm" "$path" "$@"
}

cmd_remove_backend() {
    local realm="${1:-}" target="${2:-}"
    require_arg "$realm" "realm name required"
    require_arg "$target" "volume ID or path required"
    python3 "$FFSCTL" backend remove "$realm" "$target"
}

cmd_list_backends() {
    local realm="${1:-}"
    require_arg "$realm" "realm name required"
    python3 "$FFSCTL" backend list "$realm"
}

# ---- interactive menu ----

interactive_menu() {
    echo "=============================="
    echo " FFSFS Configuration"
    echo "=============================="
    echo ""

    while true; do
        echo "What would you like to do?"
        echo ""
        echo "  1) Create a new realm"
        echo "  2) Show realm configuration"
        echo "  3) List configured realms"
        echo "  4) Set mountpoint"
        echo "  5) Set storage base"
        echo "  6) Set node name"
        echo "  7) Add a known peer"
        echo "  8) Remove a known peer"
        echo "  9) Manage storage backends"
        echo "  0) Exit"
        echo ""
        read -rp "Choice [0-9]: " choice

        case "$choice" in
            1)
                read -rp "Realm name: " realm
                read -rp "Mountpoint (e.g. ~/my-realm): " mp
                read -rp "Storage base (e.g. ~/.my-realm): " base
                cmd_init "$realm" --mountpoint "$mp" --base "$base"
                ;;
            2)
                read -rp "Realm name: " realm
                cmd_show "$realm"
                ;;
            3)
                cmd_list_realms
                ;;
            4)
                read -rp "Realm name: " realm
                read -rp "Mountpoint path: " path
                cmd_set_mountpoint "$realm" "$path"
                ;;
            5)
                read -rp "Realm name: " realm
                read -rp "Storage base path: " path
                cmd_set_base "$realm" "$path"
                ;;
            6)
                read -rp "Realm name: " realm
                read -rp "Node name: " name
                cmd_set_node_name "$realm" "$name"
                ;;
            7)
                read -rp "Realm name: " realm
                read -rp "Peer address (host:port): " peer
                cmd_add_peer "$realm" "$peer"
                ;;
            8)
                read -rp "Realm name: " realm
                read -rp "Peer address (host:port): " peer
                cmd_remove_peer "$realm" "$peer"
                ;;
            9)
                echo ""
                echo "Backend management:"
                echo "  a) List backends"
                echo "  b) Add backend"
                echo "  c) Remove backend"
                read -rp "Choice [a-c]: " bchoice
                case "$bchoice" in
                    a)
                        read -rp "Realm name: " realm
                        cmd_list_backends "$realm"
                        ;;
                    b)
                        read -rp "Realm name: " realm
                        read -rp "Backend path: " path
                        read -rp "Label (optional, enter to skip): " label
                        read -rp "Role (archive/cache, default archive): " role
                        local extra=()
                        [ -n "$label" ] && extra+=("--id" "$label")
                        [ -n "$role" ] && extra+=("--role" "$role")
                        cmd_add_backend "$realm" "$path" "${extra[@]}"
                        ;;
                    c)
                        read -rp "Realm name: " realm
                        read -rp "Volume ID or path to remove: " target
                        cmd_remove_backend "$realm" "$target"
                        ;;
                    *) echo "Invalid choice" ;;
                esac
                ;;
            0) exit 0 ;;
            *) echo "Invalid choice" ;;
        esac
        echo ""
    done
}

# ---- main dispatch ----

if [ $# -eq 0 ]; then
    interactive_menu
fi

case "${1:-}" in
    --help|-h)  usage ;;
    init)       shift; cmd_init "$@" ;;
    show)       shift; cmd_show "$@" ;;
    list)       shift; cmd_list_realms ;;
    set)        shift; cmd_set "$@" ;;
    set-mountpoint) shift; cmd_set_mountpoint "$@" ;;
    set-base)       shift; cmd_set_base "$@" ;;
    set-node-name)  shift; cmd_set_node_name "$@" ;;
    set-port)       shift; cmd_set_port "$@" ;;
    add-peer)       shift; cmd_add_peer "$@" ;;
    remove-peer)    shift; cmd_remove_peer "$@" ;;
    list-peers)     shift; cmd_list_peers ;;
    add-backend)    shift; cmd_add_backend "$@" ;;
    remove-backend) shift; cmd_remove_backend "$@" ;;
    list-backends)  shift; cmd_list_backends "$@" ;;
    *) die "unknown command: $1 (try --help)" ;;
esac
