#!/usr/bin/env python3
"""
ffsctl.py — Control tool for FFSFS

Features:
- Manage peers.conf (add/remove/ban/list)
- Query peer service statistics
- Start/stop/restart ffsfs.py as a subprocess
- Or, if run with only a mountpoint, directly mount ffsfs (fallback)

Usage examples:
  python3 ffsctl.py peers list
  python3 ffsctl.py peers add 192.168.1.12:8765
  python3 ffsctl.py peers remove 192.168.1.12:8765
  python3 ffsctl.py peers ban 192.168.1.99
  python3 ffsctl.py status
  python3 ffsctl.py start /mnt/ffs --base ~/ffsstorage
  python3 ffsctl.py stop
  python3 ffsctl.py restart
  python3 ffsctl.py /mnt/ffs --base ~/ffsstorage   # fallback direct run
"""

import os, sys, argparse, subprocess, time, requests, json

from ffsvolumes import (
    Volume, StoragePool, load_pool_config, save_pool_config,
    ROLE_PRIMARY, ROLE_ARCHIVE, VOLUME_ID_FILE,
)

CONF_DEFAULT = os.path.expanduser("~/.ffsfs/.storage/peers.conf")
FFSFS_BIN = os.path.join(os.path.dirname(__file__), "ffsfs.py")
PEERS_BIN = os.path.join(os.path.dirname(__file__), "ffspeers.py")
SERVICE_PID = os.path.expanduser("~/.ffsfs/.ffsfs.pid")
PEER_PORT = 8765

# --------------------- peers.conf helpers ---------------------

def load_peers(path=CONF_DEFAULT):
    try:
        with open(path) as f:
            return [ln.strip() for ln in f if ln.strip()]
    except FileNotFoundError:
        return []

def save_peers(peers, path=CONF_DEFAULT):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        for p in peers:
            f.write(p + "\n")

# --------------------- peer commands --------------------------

def cmd_peers(args):
    peers = load_peers(args.conf)
    if args.action == "list":
        for p in peers:
            print(p)
    elif args.action == "add":
        if args.peer not in peers:
            peers.append(args.peer)
            save_peers(peers, args.conf)
            print(f"Added {args.peer}")
        else:
            print(f"{args.peer} already present")
    elif args.action == "remove":
        if args.peer in peers:
            peers.remove(args.peer)
            save_peers(peers, args.conf)
            print(f"Removed {args.peer}")
        else:
            print(f"{args.peer} not found")
    elif args.action == "ban":
        # remove + add to banned list
        peers = [p for p in peers if p != args.peer]
        save_peers(peers, args.conf)
        banned_path = args.conf + ".banned"
        with open(banned_path, "a") as f:
            f.write(args.peer + "\n")
        print(f"Banned {args.peer}")

# --------------------- status command -------------------------

def cmd_status(args):
    url = f"http://127.0.0.1:{args.port}/status"
    try:
        r = requests.get(url, timeout=5)
        r.raise_for_status()
        data = r.json()
        print("Server:", data.get("server"), "time:", time.ctime(data.get("ts", 0)))
        for peer in data.get("peers", []):
            ago = peer.get("ago")
            ago_s = f"{int(ago)}s ago" if ago else "never"
            print(f"  {peer['peer']:<20} active={peer['active']} last={ago_s}")
    except Exception as e:
        print("Failed to fetch status:", e)

# --------------------- service control ------------------------

def _spawn_service(mountpoint, base):
    os.makedirs(os.path.dirname(SERVICE_PID), exist_ok=True)
    cmd = [sys.executable, FFSFS_BIN, mountpoint, "--base", base]
    proc = subprocess.Popen(cmd)
    with open(SERVICE_PID, "w") as f:
        f.write(str(proc.pid))
    print(f"Started ffsfs.py at pid {proc.pid}")

def cmd_start(args):
    if os.path.exists(SERVICE_PID):
        print("ffsfs already running? (pid file exists)")
        return
    _spawn_service(args.mountpoint, args.base)

def cmd_stop(args):
    try:
        with open(SERVICE_PID) as f:
            pid = int(f.read().strip())
        os.kill(pid, 15)
        os.remove(SERVICE_PID)
        print(f"Stopped ffsfs pid {pid}")
    except Exception as e:
        print("Stop failed:", e)

def cmd_restart(args):
    cmd_stop(args)
    time.sleep(1)
    cmd_start(args)

# --------------------- backend commands -----------------------

def _realm_config_path(realm: str) -> str:
    return os.path.expanduser(f"~/.ffsfs/.storage/{realm}/realm-config.json")

def _load_or_create_pool(realm: str, primary_path: str = None):
    """Load pool from realm config, or create a fresh one with the given primary path."""
    cfg = _realm_config_path(realm)
    pool = load_pool_config(cfg)
    if pool:
        return pool, cfg
    if not primary_path:
        primary_path = os.path.expanduser(f"~/.{realm}")
    primary = Volume(path=primary_path, role=ROLE_PRIMARY, label=f"{realm}-primary")
    pool = StoragePool(primary=primary)
    return pool, cfg

def cmd_backend(args):
    realm = args.realm
    action = args.action

    if action == "list":
        pool, cfg = _load_or_create_pool(realm)
        print(f"Realm: {realm}")
        print(f"Config: {cfg}")
        print()
        for vol in pool.all_volumes:
            status = vol.status()
            role = "PRIMARY" if vol is pool.primary else vol.role
            print(f"  [{status}] {vol.label}")
            print(f"          id:   {vol.vol_id}")
            print(f"          path: {vol.path}")
            print(f"          role: {role}")
            print()

    elif action == "add":
        pool, cfg = _load_or_create_pool(realm)
        path = os.path.abspath(args.path)
        if pool.find_by_path(path):
            print(f"Path already in pool: {path}")
            return
        role = args.role or ROLE_ARCHIVE
        vol = Volume(path=path, role=role, label=args.id or os.path.basename(path))
        vol.init()
        pool.add_secondary(vol)
        save_pool_config(cfg, pool, realm=realm)
        print(f"Added backend: {vol.label} ({vol.vol_id})")
        print(f"  path: {vol.path}")
        print(f"  role: {vol.role}")

    elif action == "remove":
        pool, cfg = _load_or_create_pool(realm)
        target = args.id_or_path
        vol = pool.find_by_id(target) or pool.find_by_path(target)
        if not vol:
            print(f"Not found in pool: {target}")
            return
        if vol is pool.primary:
            print("Cannot remove primary volume from pool")
            return
        pool.remove(vol.vol_id)
        save_pool_config(cfg, pool, realm=realm)
        print(f"Removed backend: {vol.label} ({vol.vol_id})")
        print(f"  Files on disk are untouched: {vol.path}")

    elif action == "register":
        pool, cfg = _load_or_create_pool(realm)
        path = os.path.abspath(args.path)
        vol = Volume.from_path(path)
        if not vol:
            print(f"No {VOLUME_ID_FILE} found at {path}")
            print("Use 'backend add' to initialize a new volume.")
            return
        existing = pool.find_by_id(vol.vol_id)
        if existing:
            print(f"Volume already registered: {existing.label} ({existing.vol_id})")
            return
        pool.add_secondary(vol)
        save_pool_config(cfg, pool, realm=realm)
        print(f"Registered backend: {vol.label} ({vol.vol_id})")
        print(f"  path: {vol.path}")
        print(f"  role: {vol.role}")

# --------------------- realm commands -------------------------

_REALM_CONFIG_KEYS = {
    "mountpoint", "base", "storage_base", "port", "bind_host",
    "node_name", "autodiscover", "known_peers", "realm",
}

def _load_realm_config(realm: str) -> dict:
    cfg_path = _realm_config_path(realm)
    if not os.path.exists(cfg_path):
        return {}
    try:
        with open(cfg_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def _save_realm_config(realm: str, data: dict) -> None:
    cfg_path = _realm_config_path(realm)
    os.makedirs(os.path.dirname(cfg_path), exist_ok=True)
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")

def cmd_realm(args):
    action = args.action
    realm = args.realm

    if action == "init":
        cfg_path = _realm_config_path(realm)
        if os.path.exists(cfg_path):
            print(f"Realm config already exists: {cfg_path}")
            return
        data = {"realm": realm}
        if args.mountpoint:
            data["mountpoint"] = os.path.abspath(args.mountpoint)
        if args.base:
            data["base"] = os.path.abspath(args.base)
            pool = StoragePool.single(data["base"])
            data["storage_pool"] = pool.to_dict()
        _save_realm_config(realm, data)
        print(f"Initialized realm config: {cfg_path}")
        print(f"  realm: {realm}")
        if "mountpoint" in data:
            print(f"  mountpoint: {data['mountpoint']}")
        if "base" in data:
            print(f"  base: {data['base']}")

    elif action == "show":
        data = _load_realm_config(realm)
        if not data:
            cfg_path = _realm_config_path(realm)
            print(f"No config found for realm '{realm}' ({cfg_path})")
            print("Run: ffsctl.py realm init <realm> [--mountpoint <path>] [--base <path>]")
            return
        cfg_path = _realm_config_path(realm)
        print(f"Realm: {realm}")
        print(f"Config: {cfg_path}")
        print()
        for key, value in data.items():
            if key == "storage_pool":
                print(f"  storage_pool:")
                primary = value.get("primary", {})
                print(f"    primary: {primary.get('path', '?')} ({primary.get('role', '?')})")
                for b in value.get("backends", []):
                    print(f"    backend: {b.get('path', '?')} ({b.get('role', '?')})")
            elif key == "known_peers":
                print(f"  known_peers:")
                for p in value:
                    print(f"    - {p}")
            else:
                print(f"  {key}: {value}")

    elif action == "set":
        data = _load_realm_config(realm)
        if not data:
            data = {"realm": realm}
        key = args.key
        value = args.value
        if key not in _REALM_CONFIG_KEYS:
            print(f"Unknown config key: {key}")
            print(f"Valid keys: {', '.join(sorted(_REALM_CONFIG_KEYS))}")
            return
        if key == "autodiscover":
            value = value.lower() in ("1", "true", "yes", "on")
        elif key == "port":
            try:
                value = int(value)
            except ValueError:
                print("port must be an integer")
                return
        elif key in ("mountpoint", "base", "storage_base"):
            value = os.path.abspath(value)
        data[key] = value
        _save_realm_config(realm, data)
        print(f"Set {key} = {value}")

    elif action == "list":
        base_dir = os.path.expanduser("~/.ffsfs/.storage")
        if not os.path.isdir(base_dir):
            print("No realms configured yet.")
            return
        found = False
        for entry in sorted(os.listdir(base_dir)):
            cfg = os.path.join(base_dir, entry, "realm-config.json")
            if os.path.isfile(cfg):
                found = True
                print(f"  {entry}")
        if not found:
            print("No realms configured yet.")

# --------------------- fallback direct run --------------------

def fallback_run(argv):
    # call ffsfs.py directly with same args
    cmd = [sys.executable, FFSFS_BIN] + argv
    os.execv(sys.executable, cmd)

# --------------------- main -------------------------

def main():
    ap = argparse.ArgumentParser(prog="ffsctl", add_help=True)
    sub = ap.add_subparsers(dest="cmd")

    sp = sub.add_parser("peers", help="manage peers.conf")
    sp.add_argument("action", choices=["list", "add", "remove", "ban"])
    sp.add_argument("peer", nargs="?")
    sp.add_argument("--conf", default=CONF_DEFAULT)
    sp.set_defaults(func=cmd_peers)

    ss = sub.add_parser("status", help="show peer service status")
    ss.add_argument("--port", type=int, default=PEER_PORT)
    ss.set_defaults(func=cmd_status)

    sstart = sub.add_parser("start", help="start ffsfs.py as service")
    sstart.add_argument("mountpoint")
    sstart.add_argument("--base", required=True)
    sstart.set_defaults(func=cmd_start)

    sstop = sub.add_parser("stop", help="stop ffsfs service")
    sstop.set_defaults(func=cmd_stop)

    srestart = sub.add_parser("restart", help="restart ffsfs service")
    srestart.add_argument("mountpoint")
    srestart.add_argument("--base", required=True)
    srestart.set_defaults(func=cmd_restart)

    sb = sub.add_parser("backend", help="manage storage backends")
    sb.add_argument("action", choices=["list", "add", "remove", "register"])
    sb.add_argument("realm", help="realm name")
    sb.add_argument("path", nargs="?", help="backend path (for add/register)")
    sb.add_argument("id_or_path", nargs="?", help="volume ID or path (for remove)")
    sb.add_argument("--id", default=None, help="label for the new backend")
    sb.add_argument("--role", default=None, help="backend role (archive, cache)")
    sb.set_defaults(func=cmd_backend)

    sr = sub.add_parser("realm", help="manage realm configuration")
    sr.add_argument("action", choices=["init", "show", "set", "list"])
    sr.add_argument("realm", nargs="?", help="realm name")
    sr.add_argument("key", nargs="?", help="config key (for set)")
    sr.add_argument("value", nargs="?", help="config value (for set)")
    sr.add_argument("--mountpoint", default=None, help="mountpoint path (for init)")
    sr.add_argument("--base", default=None, help="storage base path (for init)")
    sr.set_defaults(func=cmd_realm)

    args, rest = ap.parse_known_args()

    if not args.cmd:
        # fallback: run ffsfs.py directly with whatever was passed
        fallback_run(sys.argv[1:])
    else:
        args.func(args)

if __name__ == "__main__":
    main()

