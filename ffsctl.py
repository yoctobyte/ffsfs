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
            print(f"          mirror: {'yes' if vol.mirror else 'no'}")
            if vol.media:
                print(f"          media: {vol.media}")
            if vol.max_bytes is not None:
                print(f"          max_bytes: {vol.max_bytes}")
            if vol.max_file_size is not None:
                print(f"          max_file_size: {vol.max_file_size}")
            if vol.reserve_bytes is not None:
                print(f"          reserve_bytes: {vol.reserve_bytes}")
            print()

    elif action == "add":
        pool, cfg = _load_or_create_pool(realm)
        path = os.path.abspath(args.path)
        if pool.find_by_path(path):
            print(f"Path already in pool: {path}")
            return
        role = args.role or ROLE_ARCHIVE
        vol = Volume(
            path=path,
            role=role,
            label=args.id or os.path.basename(path),
            mirror=bool(getattr(args, "mirror", False)),
            media=getattr(args, "media", None),
            max_bytes=getattr(args, "max_bytes", None),
            max_file_size=getattr(args, "max_file_size", None),
            reserve_bytes=getattr(args, "reserve_bytes", None),
        )
        vol.init()
        pool.add_secondary(vol)
        save_pool_config(cfg, pool, realm=realm)
        print(f"Added backend: {vol.label} ({vol.vol_id})")
        print(f"  path: {vol.path}")
        print(f"  role: {vol.role}")
        print(f"  mirror: {'yes' if vol.mirror else 'no'}")

    elif action == "remove":
        pool, cfg = _load_or_create_pool(realm)
        target = args.id_or_path or args.path
        if not target:
            print("volume ID or path required")
            return
        vol = pool.find_by_id(target) or pool.find_by_path(target) or pool.find_by_label(target)
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
    "node_role", "node_availability", "node_storage_profile",
    "peer_trust", "peer_transport", "realm_secret",
}

_PEER_TRUST_VALUES = {"realm_secret", "manual"}
_PEER_TRANSPORT_VALUES = {"http", "https"}

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
        if getattr(args, "secret", None) and getattr(args, "passphrase", None):
            print("Cannot use both --secret and --passphrase")
            return
        if getattr(args, "secret", None):
            try:
                bytes.fromhex(args.secret)
            except ValueError:
                print("--secret must be a valid hex string")
                return
            if len(args.secret) < 32:
                print("--secret too short (minimum 32 hex chars / 16 bytes)")
                return
            secret = args.secret
        elif getattr(args, "passphrase", None):
            from ffspeer_auth import secret_from_passphrase
            secret = secret_from_passphrase(args.passphrase, realm)
        else:
            from ffspeer_auth import generate_realm_secret
            secret = generate_realm_secret()
        data = {"realm": realm, "realm_secret": secret}
        if args.mountpoint:
            data["mountpoint"] = os.path.abspath(args.mountpoint)
        if args.base:
            data["base"] = os.path.abspath(args.base)
            pool = StoragePool.single(data["base"])
            data["storage_pool"] = pool.to_dict()
        _save_realm_config(realm, data)
        print(f"Initialized realm config: {cfg_path}")
        print(f"  realm: {realm}")
        secret_src = "(provided)" if getattr(args, 'secret', None) else "(from passphrase)" if getattr(args, 'passphrase', None) else "(generated)"
        print(f"  realm_secret: {secret_src}")
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
            elif key == "realm_secret":
                print(f"  realm_secret: {'*' * 8} (use realm-config.json to view)")
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
        elif key == "node_role":
            from ffsvolumes import NODE_ROLES
            if value not in NODE_ROLES:
                print(f"Unknown node_role: {value}")
                print(f"Valid roles: {', '.join(sorted(NODE_ROLES))}")
                return
        elif key == "node_availability":
            from ffsvolumes import NODE_AVAILABILITIES
            if value not in NODE_AVAILABILITIES:
                print(f"Unknown node_availability: {value}")
                print(f"Valid values: {', '.join(sorted(NODE_AVAILABILITIES))}")
                return
        elif key == "node_storage_profile":
            from ffsvolumes import NODE_STORAGE_PROFILES
            if value not in NODE_STORAGE_PROFILES:
                print(f"Unknown node_storage_profile: {value}")
                print(f"Valid values: {', '.join(sorted(NODE_STORAGE_PROFILES))}")
                return
        elif key == "peer_trust":
            if value not in _PEER_TRUST_VALUES:
                print(f"Unknown peer_trust: {value}")
                print(f"Valid values: {', '.join(sorted(_PEER_TRUST_VALUES))}")
                return
        elif key == "peer_transport":
            if value not in _PEER_TRANSPORT_VALUES:
                print(f"Unknown peer_transport: {value}")
                print(f"Valid values: {', '.join(sorted(_PEER_TRANSPORT_VALUES))}")
                return
        elif key == "realm_secret":
            try:
                bytes.fromhex(value)
            except ValueError:
                print("realm_secret must be a hex string")
                return
            if len(value) < 32:
                print("realm_secret too short (minimum 32 hex chars / 16 bytes)")
                return
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

# --------------------- role / sync / ratelimit commands ---------------

def cmd_role(args):
    from ffsvolumes import (
        NODE_ROLES, DEFAULT_NODE_ROLE,
        DEFAULT_NODE_AVAILABILITY, DEFAULT_NODE_STORAGE_PROFILE,
        NODE_AVAILABILITIES, NODE_STORAGE_PROFILES,
    )
    realm = args.realm
    data = _load_realm_config(realm)
    if not data:
        print(f"No config found for realm '{realm}'. Run: ffsctl realm init {realm}")
        return
    if args.role is None:
        current = data.get("node_role", DEFAULT_NODE_ROLE)
        availability = data.get("node_availability", DEFAULT_NODE_AVAILABILITY)
        storage = data.get("node_storage_profile", DEFAULT_NODE_STORAGE_PROFILE)
        print(f"node_role: {current}")
        print(f"node_availability: {availability}")
        print(f"node_storage_profile: {storage}")
        print(f"valid: {', '.join(sorted(NODE_ROLES))}")
        print(f"valid availability: {', '.join(sorted(NODE_AVAILABILITIES))}")
        print(f"valid storage: {', '.join(sorted(NODE_STORAGE_PROFILES))}")
        return
    if args.role not in NODE_ROLES:
        print(f"Unknown node_role: {args.role}")
        print(f"Valid: {', '.join(sorted(NODE_ROLES))}")
        return
    data["node_role"] = args.role
    _save_realm_config(realm, data)
    print(f"Set node_role = {args.role}")


def cmd_sync(args):
    from ffssync import SyncPolicy, SYNC_MODES
    realm = args.realm
    data = _load_realm_config(realm)
    if not data:
        print(f"No config found for realm '{realm}'. Run: ffsctl realm init {realm}")
        return

    if args.action == "show":
        try:
            policy = SyncPolicy.from_config(data.get("node_role"), data.get("sync"))
        except Exception as e:
            print(f"invalid config: {e}")
            return
        print(f"Realm: {realm}")
        print(f"  node_role:        {policy.role}")
        print(f"  mode:             {policy.mode}")
        print(f"  prefixes:         {policy.prefixes or '[all]'}")
        print(f"  interval_secs:    {policy.interval_secs}")
        if policy.cache_max_bytes is not None:
            print(f"  cache_max_bytes:  {policy.cache_max_bytes}")
        return

    if args.action == "set":
        key = args.key
        value = args.value
        if key not in {"mode", "prefixes", "interval_secs", "cache_max_bytes"}:
            print(f"Unknown sync key: {key}")
            print("Valid keys: mode, prefixes, interval_secs, cache_max_bytes")
            return
        sync_cfg = dict(data.get("sync") or {})
        if key == "mode":
            if value not in SYNC_MODES:
                print(f"Unknown mode: {value} (valid: {sorted(SYNC_MODES)})")
                return
            sync_cfg["mode"] = value
        elif key == "prefixes":
            sync_cfg["prefixes"] = [p.strip() for p in value.split(",") if p.strip()]
        elif key == "interval_secs":
            try:
                sync_cfg["interval_secs"] = float(value)
            except ValueError:
                print("interval_secs must be numeric")
                return
        elif key == "cache_max_bytes":
            try:
                v = int(value)
            except ValueError:
                print("cache_max_bytes must be integer (bytes)")
                return
            if v <= 0:
                sync_cfg.pop("cache_max_bytes", None)
            else:
                sync_cfg["cache_max_bytes"] = v
        data["sync"] = sync_cfg
        _save_realm_config(realm, data)
        print(f"Set sync.{key} = {sync_cfg.get(key)!r}")
        return

    if args.action == "run-once":
        # Construct a backend without mounting FUSE and run one sync pass.
        from ffsvolumes import StoragePool
        from ffsfs import StorageBackend
        try:
            import ffspeers as peers_mod
        except Exception:
            peers_mod = None
        pool_data = data.get("storage_pool")
        if pool_data:
            pool = StoragePool.from_dict(pool_data)
            base_path = pool.primary.path
        else:
            base_path = data.get("base") or data.get("storage_base")
            if not base_path:
                print("realm has no storage configured")
                return
            pool = None
        from ffsratelimit import RateLimits
        rate_limits = RateLimits.from_config(data.get("rate_limits"))
        backend = StorageBackend(base_path, realm, pool=pool,
                                 rate_limits=rate_limits)
        if peers_mod is not None:
            try:
                peers_mod.set_realm(realm)
                peers_mod.register_local_backend(backend)
                if hasattr(peers_mod, "set_rate_limits"):
                    peers_mod.set_rate_limits(rate_limits)
                for kp in data.get("known_peers", []) or []:
                    kp = str(kp).strip()
                    if kp and kp not in peers_mod._known_peers:
                        peers_mod._known_peers.append(kp)
                if hasattr(peers_mod, "refresh_peer_filecache_once"):
                    peers_mod.refresh_peer_filecache_once(force=True)
            except Exception as e:
                print(f"warning: peer setup failed: {e}")
        try:
            policy = SyncPolicy.from_config(data.get("node_role"), data.get("sync"))
        except Exception as e:
            print(f"invalid config: {e}")
            return
        from ffssync import SyncWorker
        worker = SyncWorker(backend, peers_mod, policy, rate_limits)
        active = worker.run_active_once()
        evicted = worker.run_eviction_once()
        print(f"active: {active}")
        print(f"eviction: {evicted}")
        status = worker.status()
        if status.get("failed_paths"):
            print(f"failed_paths: {status['failed_paths']}")

    if args.action == "status":
        import time as _time
        from ffsvolumes import StoragePool, ROLE_CACHE
        try:
            import ffspeers as peers_mod
        except Exception:
            peers_mod = None

        try:
            policy = SyncPolicy.from_config(data.get("node_role"), data.get("sync"))
        except Exception as e:
            print(f"invalid config: {e}")
            return

        print(f"Realm: {realm}")
        print(f"  node_role: {policy.role}")
        print(f"  sync_mode: {policy.mode}")
        print(f"  interval: {policy.interval_secs}s")
        if policy.prefixes:
            print(f"  prefixes: {', '.join(policy.prefixes)}")
        else:
            print(f"  prefixes: (whole realm)")
        if policy.cache_max_bytes:
            print(f"  cache_max: {policy.cache_max_bytes} bytes")

        print()
        print("Peers:")
        if peers_mod is not None:
            try:
                peers_mod.set_realm(realm)
                for kp in data.get("known_peers", []) or []:
                    kp = str(kp).strip()
                    if kp and kp not in peers_mod._known_peers:
                        peers_mod._known_peers.append(kp)
                if hasattr(peers_mod, "refresh_peer_filecache_once"):
                    peers_mod.refresh_peer_filecache_once(force=True)
            except Exception as e:
                print(f"  (peer setup failed: {e})")

            now = _time.time()
            cache = getattr(peers_mod, "_peer_cache", {}) or {}
            last_seen = getattr(peers_mod, "_last_seen", {}) or {}
            known = getattr(peers_mod, "_known_peers", []) or []

            if not known:
                print("  (none configured)")
            for peer in known:
                files_dict = (cache.get(peer) or {}).get("files", {})
                n_vpaths = len(files_dict)
                last = last_seen.get(peer)
                if last:
                    ago = int(now - last)
                    last_str = f"{ago}s ago"
                else:
                    last_str = "never"
                cache_ts = (cache.get(peer) or {}).get("last_sync", 0)
                if cache_ts:
                    cache_ago = int(now - cache_ts)
                    cache_str = f"{cache_ago}s ago"
                else:
                    cache_str = "never"
                print(f"  {peer:<22} files={n_vpaths:<5} last_seen={last_str:<10} cache_refresh={cache_str}")
        else:
            print("  (peer module unavailable)")

        print()
        print("Failed paths:")
        port = data.get("port")
        live_status = None
        if port:
            try:
                r = requests.get(f"http://127.0.0.1:{port}/sync-status", timeout=3)
                if r.status_code == 200:
                    live_status = r.json()
            except Exception:
                pass

        if live_status:
            failed = live_status.get("failed_paths", {})
            if not failed:
                print("  (none)")
            for vpath, info in failed.items():
                retry_in = max(0, int(info.get("next_retry", 0) - _time.time()))
                print(f"  {vpath}: attempts={info['attempts']} "
                      f"error={info['last_error']!r} retry_in={retry_in}s")
            conflicts = live_status.get("conflicts", {})
            if conflicts:
                print()
                print(f"Conflicts: {len(conflicts)}")
                for vpath in sorted(conflicts):
                    print(f"  {vpath}")
        else:
            print("  (service not running — no live failure data available)")

        pool_data = data.get("storage_pool")
        if pool_data:
            pool = StoragePool.from_dict(pool_data)
            print()
            print("Storage volumes:")
            for vol in pool.all_volumes:
                online = vol.is_online()
                used = vol.used_bytes() if online else 0
                role_str = vol.role
                status_str = "online" if online else "OFFLINE"
                print(f"  {vol.path}: role={role_str} status={status_str} used={used} bytes")
                if vol.role == ROLE_CACHE and policy.cache_max_bytes:
                    pct = int(100 * used / policy.cache_max_bytes) if policy.cache_max_bytes else 0
                    print(f"    cache pressure: {pct}% ({used}/{policy.cache_max_bytes})")


def cmd_ratelimit(args):
    from ffsratelimit import RateLimits, RATE_LIMIT_KEYS
    realm = args.realm
    data = _load_realm_config(realm)
    if not data:
        print(f"No config found for realm '{realm}'. Run: ffsctl realm init {realm}")
        return

    if args.action == "show":
        rl = RateLimits.from_config(data.get("rate_limits"))
        print(f"Realm: {realm}")
        for k, v in rl.to_dict().items():
            label = "unlimited" if v == 0 else f"{v} B/s"
            print(f"  {k}: {label}")
        return

    if args.action == "set":
        key = args.key
        if key not in RATE_LIMIT_KEYS:
            print(f"Unknown rate-limit key: {key}")
            print(f"Valid keys: {', '.join(RATE_LIMIT_KEYS)}")
            return
        try:
            v = int(args.value)
        except ValueError:
            print("value must be an integer (bytes/sec, 0 = unlimited)")
            return
        if v < 0:
            print("value must be >= 0")
            return
        rl_cfg = dict(data.get("rate_limits") or {})
        rl_cfg[key] = v
        data["rate_limits"] = rl_cfg
        _save_realm_config(realm, data)
        print(f"Set rate_limits.{key} = {v}")


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
    sb.add_argument("id_or_path", nargs="?", help="volume ID, label, or path (for remove)")
    sb.add_argument("--id", default=None, help="label for the new backend")
    sb.add_argument("--role", default=None, help="backend role (archive, cache)")
    sb.add_argument("--mirror", action="store_true", help="replicate committed writes to this backend")
    sb.add_argument("--media", default=None, help="storage media hint (ssd, hdd, network)")
    sb.add_argument("--max-bytes", type=int, default=None, help="maximum bytes this backend should use")
    sb.add_argument("--max-file-size", type=int, default=None, help="largest file this backend should accept")
    sb.add_argument("--reserve-bytes", type=int, default=None, help="free bytes to reserve on this backend")
    sb.set_defaults(func=cmd_backend)

    sr = sub.add_parser("realm", help="manage realm configuration")
    sr.add_argument("action", choices=["init", "show", "set", "list"])
    sr.add_argument("realm", nargs="?", help="realm name")
    sr.add_argument("key", nargs="?", help="config key (for set)")
    sr.add_argument("value", nargs="?", help="config value (for set)")
    sr.add_argument("--mountpoint", default=None, help="mountpoint path (for init)")
    sr.add_argument("--base", default=None, help="storage base path (for init)")
    sr.add_argument("--secret", default=None, help="existing realm secret hex (for joining a realm)")
    sr.add_argument("--passphrase", default=None, help="derive realm secret from a passphrase")
    sr.set_defaults(func=cmd_realm)

    sro = sub.add_parser("role", help="show or set the node storage role")
    sro.add_argument("realm", help="realm name")
    sro.add_argument("role", nargs="?", help="new node role (omit to show)")
    sro.set_defaults(func=cmd_role)

    sy = sub.add_parser("sync", help="manage background sync policy")
    sy.add_argument("realm", help="realm name")
    sy.add_argument("action", choices=["show", "set", "run-once", "status"])
    sy.add_argument("key", nargs="?", help="sync key (mode|prefixes|interval_secs|cache_max_bytes)")
    sy.add_argument("value", nargs="?", help="value (for set)")
    sy.set_defaults(func=cmd_sync)

    srl = sub.add_parser("ratelimit", help="manage rate-limit configuration (0 = unlimited)")
    srl.add_argument("realm", help="realm name")
    srl.add_argument("action", choices=["show", "set"])
    srl.add_argument("key", nargs="?", help="rate-limit key (disk_fg_bps|disk_bg_bps|net_fg_bps|net_bg_bps)")
    srl.add_argument("value", nargs="?", help="bytes/sec (for set)")
    srl.set_defaults(func=cmd_ratelimit)

    args, rest = ap.parse_known_args()

    if not args.cmd:
        # fallback: run ffsfs.py directly with whatever was passed
        fallback_run(sys.argv[1:])
    else:
        args.func(args)

if __name__ == "__main__":
    main()
