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

import os, sys, argparse, subprocess, time, requests

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

    args, rest = ap.parse_known_args()

    if not args.cmd:
        # fallback: run ffsfs.py directly with whatever was passed
        fallback_run(sys.argv[1:])
    else:
        args.func(args)

if __name__ == "__main__":
    main()

