#!/usr/bin/env python3
"""
ffssetup.py - console setup and edit app for FFSFS.

The setup app edits the same realm-config.json files used by launch.sh and
ffsctl.py. It saves after each step, but marks configs inactive until the final
activation step succeeds.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import re
import secrets
import socket
import subprocess
import sys
from dataclasses import dataclass
from typing import Iterable, List, Optional

from ffsctl import _load_realm_config, _realm_config_path, _save_realm_config
from ffspeer_auth import generate_realm_secret, secret_from_passphrase
from ffsvolumes import (
    DEFAULT_NODE_AVAILABILITY,
    DEFAULT_NODE_ROLE,
    DEFAULT_NODE_STORAGE_PROFILE,
    DEVICE_CLASSES,
    DEVICE_EXTERNAL,
    DEVICE_INTERNAL,
    DEVICE_NETWORK,
    DEVICE_OPTICAL,
    DEVICE_SD,
    DEVICE_USB,
    JOB_GENERAL,
    MEDIA_HDD,
    MEDIA_NETWORK,
    MEDIA_SSD,
    ROLE_ARCHIVE,
    ROLE_PRIMARY,
    StoragePool,
    Volume,
)


SETUP_SCHEMA_VERSION = 1
ADMIN_HASH_ITERATIONS = 200_000

# Realm collaboration intent. Recorded so future move/rename/conflict tuning can
# read it; no resolution policy is enforced yet (see
# agents/cold_archive_design.md + the conflict-policy-deferred note).
COLLABORATION_SOLO = "solo"        # single curator: last-write-wins + warn
COLLABORATION_SHARED = "shared"    # multi-writer: surface conflicts (future)
COLLABORATION_MODES = {COLLABORATION_SOLO, COLLABORATION_SHARED}
DEFAULT_COLLABORATION = COLLABORATION_SOLO

# Backend assumption defaults by device class. Intent only: max_file_size IS
# enforced by existing write routing (can_accept_write), but job/prefix
# preference and "high-prio-small" routing are future work (storage policy).
_MB = 1024 * 1024
_BACKEND_ASSUMPTIONS = {
    # External HDD/SSD or dock: removable but a FULL-SIZE disk — mirror backup,
    # NO small-file cap (this is the one for a 2 TB USB drive).
    DEVICE_EXTERNAL: {"media": MEDIA_HDD,     "mirror": True,  "role": ROLE_ARCHIVE, "max_file_size": None},
    # Small flash key / SD card: removable, small-but-important backup -> cap.
    DEVICE_USB:      {"media": MEDIA_HDD,     "mirror": True,  "role": ROLE_ARCHIVE, "max_file_size": 64 * _MB},
    DEVICE_SD:       {"media": MEDIA_HDD,     "mirror": True,  "role": ROLE_ARCHIVE, "max_file_size": 16 * _MB},
    # Write-once cold archive (sealed-volume concept is future); mirror target.
    DEVICE_OPTICAL:  {"media": MEDIA_HDD,     "mirror": True,  "role": ROLE_ARCHIVE, "max_file_size": None},
    # Big workstation disk: bulk replica, no size cap, not a mirror by default.
    DEVICE_INTERNAL: {"media": MEDIA_HDD,     "mirror": False, "role": ROLE_ARCHIVE, "max_file_size": None},
    # NAS/dumb networked storage: bulk, mirror.
    DEVICE_NETWORK:  {"media": MEDIA_NETWORK, "mirror": True,  "role": ROLE_ARCHIVE, "max_file_size": None},
}


def suggest_backend_defaults(device_class: Optional[str]) -> dict:
    """Return suggested {media, mirror, role, max_file_size} for a device class.

    Pure suggestion — the caller (setup) prefills these and lets the user
    override. Unknown/None device class yields neutral defaults.
    """
    base = {"media": None, "mirror": False, "role": ROLE_ARCHIVE, "max_file_size": None}
    base.update(_BACKEND_ASSUMPTIONS.get(device_class or "", {}))
    return base

ONLINE_EXPECTATIONS = {
    "always": {
        "label": "always online",
        "node_availability": "always_online",
    },
    "hours": {
        "label": "hours per day",
        "node_availability": "intermittent",
    },
    "casual": {
        "label": "casual/on demand",
        "node_availability": "on_demand",
    },
    "unknown": {
        "label": "do not know yet",
        "node_availability": DEFAULT_NODE_AVAILABILITY,
    },
}

BACKEND_POLICIES = {
    "greedy": {
        "label": "greedy - use available storage freely",
        "node_role": "replica_storage",
        "node_storage_profile": "bulk_storage",
        "sync": {"mode": "active", "prefixes": []},
    },
    "balanced": {
        "label": "redundancy balanced",
        "node_role": "shared_storage",
        "node_storage_profile": "limited",
        "sync": {"mode": "active", "prefixes": []},
    },
    "minimal": {
        "label": "minimal local cache",
        "node_role": "cache_limited",
        "node_storage_profile": "limited",
        "sync": {"mode": "lazy", "prefixes": []},
    },
    "meta": {
        "label": "only metadata/access node",
        "node_role": "access_only",
        "node_storage_profile": "cache_only",
        "sync": {"mode": "lazy", "prefixes": []},
    },
    "capped": {
        "label": "capped local cache",
        "node_role": "cache_limited",
        "node_storage_profile": "limited",
        "sync": {"mode": "active", "prefixes": []},
    },
}


def config_base() -> str:
    return os.path.expanduser("~/.ffsfs/.storage")


from ffsutils import default_port_for_realm  # single source of truth


def _cfg_path(realm: str) -> str:
    return _realm_config_path(realm)


def _ensure_setup_state(data: dict) -> dict:
    state = dict(data.get("setup_state") or {})
    state.setdefault("schema_version", SETUP_SCHEMA_VERSION)
    state.setdefault("activated", False)
    state.setdefault("completed_steps", [])
    data["setup_state"] = state
    return state


def _mark_step(data: dict, step: str) -> None:
    state = _ensure_setup_state(data)
    steps = list(state.get("completed_steps") or [])
    if step not in steps:
        steps.append(step)
    state["completed_steps"] = steps


def _save_inactive(realm: str, data: dict, step: Optional[str] = None) -> None:
    state = _ensure_setup_state(data)
    state["activated"] = False
    if step:
        _mark_step(data, step)
    _save_realm_config(realm, data)


def hash_admin_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("ascii"), ADMIN_HASH_ITERATIONS
    ).hex()
    return f"pbkdf2_sha256${ADMIN_HASH_ITERATIONS}${salt}${digest}"


def generate_admin_password() -> str:
    return secrets.token_urlsafe(18)


def list_realms() -> List[str]:
    base = config_base()
    if not os.path.isdir(base):
        return []
    realms = []
    for entry in sorted(os.listdir(base)):
        if os.path.isfile(os.path.join(base, entry, "realm-config.json")):
            realms.append(entry)
    return realms


def load_realm(realm: str) -> dict:
    return _load_realm_config(realm)


def setup_defaults(realm: str, data: Optional[dict] = None) -> dict:
    data = dict(data or {})
    data.setdefault("realm", realm)
    data.setdefault("node_name", socket.gethostname())
    data.setdefault("host_alias", data.get("node_name") or socket.gethostname())
    data.setdefault("peer_trust", "realm_secret")
    data.setdefault("peer_transport", "http")
    data.setdefault("port", default_port_for_realm(realm))
    data.setdefault("trust_unknown_peers", False)
    data.setdefault("autodiscover", True)
    data.setdefault("node_role", DEFAULT_NODE_ROLE)
    data.setdefault("node_availability", DEFAULT_NODE_AVAILABILITY)
    data.setdefault("node_storage_profile", DEFAULT_NODE_STORAGE_PROFILE)
    data.setdefault("sync", {"mode": "lazy", "prefixes": []})
    data.setdefault("online_expectation", "unknown")
    data.setdefault("backend_policy", "minimal")
    data.setdefault("collaboration", DEFAULT_COLLABORATION)
    _ensure_setup_state(data)
    return data


def set_collaboration(realm: str, mode: str) -> None:
    """Record the realm's collaboration intent (solo|shared). Intent only —
    no conflict-resolution policy is enforced from it yet."""
    if mode not in COLLABORATION_MODES:
        raise ValueError(f"unknown collaboration mode: {mode}")
    data = setup_defaults(realm, load_realm(realm))
    data["collaboration"] = mode
    _save_inactive(realm, data, "collaboration")


def create_realm_config(
    realm: str,
    mountpoint: str,
    primary_base: str,
    passphrase: Optional[str] = None,
    secret: Optional[str] = None,
) -> dict:
    if secret and passphrase:
        raise ValueError("use either secret or passphrase, not both")
    if secret:
        bytes.fromhex(secret)
        if len(secret) < 32:
            raise ValueError("realm secret must be at least 32 hex chars")
        realm_secret = secret
    elif passphrase:
        realm_secret = secret_from_passphrase(passphrase, realm)
    else:
        realm_secret = generate_realm_secret()

    base = os.path.abspath(os.path.expanduser(primary_base))
    mount = os.path.abspath(os.path.expanduser(mountpoint))
    primary = Volume(path=base, role=ROLE_PRIMARY, label=f"{realm}-primary")
    primary.init()
    data = setup_defaults(realm)
    data.update({
        "realm_secret": realm_secret,
        "mountpoint": mount,
        "base": base,
        "storage_pool": StoragePool(primary=primary).to_dict(),
    })
    _save_inactive(realm, data, "realm")
    return data


def set_realm_secret(realm: str, passphrase: Optional[str] = None,
                     secret: Optional[str] = None) -> str:
    """Replace the realm secret. Pass a shared `passphrase` (same on every host
    in the realm), an exact hex `secret`, or neither to generate a new random
    one. Keeps the realm active; the running service must restart to pick it up.
    Returns the new secret."""
    data = load_realm(realm)
    if not data:
        raise ValueError(f"realm not configured: {realm}")
    if secret and passphrase:
        raise ValueError("use either secret or passphrase, not both")
    if secret:
        bytes.fromhex(secret)
        if len(secret) < 32:
            raise ValueError("realm secret must be at least 32 hex chars")
        new_secret = secret
    elif passphrase:
        new_secret = secret_from_passphrase(passphrase, realm)
    else:
        new_secret = generate_realm_secret()
    data["realm_secret"] = new_secret
    _save_realm_config(realm, data)   # keep activation state
    return new_secret


def prompt_realm_secret(realm: str) -> None:
    data = load_realm(realm) or {}
    cur = data.get("realm_secret")
    print("Realm secret — the shared key every host in this realm must share.")
    print("Peers with a different secret connect but fail auth (403).")
    if cur:
        print(f"  current: {cur[:8]}... ({len(cur)} chars)")
    print("Enter the SAME passphrase used on the other hosts (it derives the")
    print("secret deterministically), or paste an exact hex secret, or type")
    print("'show' to print the full current secret to copy, or blank to keep.")
    val = _prompt("Passphrase / hex secret / 'show'")
    if not val:
        return
    if val == "show":
        print(f"  realm_secret = {cur}")
        return
    try:
        is_hex = len(val) >= 32 and all(c in "0123456789abcdefABCDEF" for c in val)
        if is_hex:
            set_realm_secret(realm, secret=val)
        else:
            set_realm_secret(realm, passphrase=val)
        print("Realm secret updated. Restart the service for it to take effect,")
        print("and use the SAME passphrase/secret on every host in this realm.")
    except Exception as e:
        print(f"Could not set secret: {e}")


def add_backend(
    realm: str,
    path: str,
    label: Optional[str] = None,
    role: Optional[str] = None,
    mirror: Optional[bool] = None,
    media: Optional[str] = None,
    device_class: Optional[str] = None,
    job: Optional[str] = None,
    job_prefix: Optional[str] = None,
    max_file_size: Optional[int] = None,
) -> Volume:
    data = load_realm(realm)
    if not data:
        raise ValueError(f"realm not configured: {realm}")
    if device_class is not None and device_class not in DEVICE_CLASSES:
        raise ValueError(f"unknown device class: {device_class}")
    # Fill unspecified attributes from device-class assumptions (intent only).
    sugg = suggest_backend_defaults(device_class)
    role = role if role is not None else sugg["role"]
    mirror = sugg["mirror"] if mirror is None else mirror
    media = media if media is not None else sugg["media"]
    max_file_size = max_file_size if max_file_size is not None else sugg["max_file_size"]
    # A themed job overrides the "general" default and scopes the device to a
    # vpath prefix (recorded; routing enforcement is future work).
    if job_prefix:
        job = job or job_prefix
    else:
        job = job or JOB_GENERAL
    pool = StoragePool.from_dict(data.get("storage_pool") or StoragePool.single(data.get("base")).to_dict())
    abs_path = os.path.abspath(os.path.expanduser(path))
    if pool.find_by_path(abs_path):
        raise ValueError(f"backend already registered: {abs_path}")
    vol = Volume(
        path=abs_path,
        label=label or os.path.basename(abs_path) or "backend",
        role=role,
        mirror=mirror,
        media=media,
        max_file_size=max_file_size,
        device_class=device_class,
        job=job,
        job_prefix=job_prefix or None,
    )
    vol.init()
    pool.add_secondary(vol)
    data["storage_pool"] = pool.to_dict()
    _save_inactive(realm, data, "backends")
    return vol


def remove_backend(realm: str, target: str) -> Volume:
    data = load_realm(realm)
    if not data:
        raise ValueError(f"realm not configured: {realm}")
    pool = StoragePool.from_dict(data.get("storage_pool"))
    vol = pool.find_by_id(target) or pool.find_by_label(target) or pool.find_by_path(target)
    if not vol:
        raise ValueError(f"backend not found: {target}")
    if vol is pool.primary or vol.vol_id == pool.primary.vol_id:
        raise ValueError("cannot remove primary backend")
    pool.remove(vol.vol_id)
    data["storage_pool"] = pool.to_dict()
    _save_inactive(realm, data, "backends")
    return vol


def add_peer(realm: str, peer: str, approved: bool = False) -> None:
    data = load_realm(realm)
    if not data:
        raise ValueError(f"realm not configured: {realm}")
    key = "approved_peers" if approved else "known_peers"
    peers = dedupe_peer_endpoints(data.get(key, []))
    if peer not in peers:
        peers.append(peer)
    data[key] = peers
    _save_inactive(realm, data, "peers")


def remove_peer(realm: str, peer: str, approved: bool = False) -> None:
    data = load_realm(realm)
    if not data:
        raise ValueError(f"realm not configured: {realm}")
    key = "approved_peers" if approved else "known_peers"
    peers = [p for p in dedupe_peer_endpoints(data.get(key, [])) if p != peer]
    if peers:
        data[key] = peers
    else:
        data.pop(key, None)
    _save_inactive(realm, data, "peers")


def set_node_identity(realm: str, node_name: str, host_alias: str, admin_password: Optional[str]) -> dict:
    data = setup_defaults(realm, load_realm(realm))
    data["node_name"] = node_name
    data["host_alias"] = host_alias
    if admin_password is None:
        admin_password = generate_admin_password()
        data["admin_password_generated"] = True
    else:
        data["admin_password_generated"] = False
    data["admin_password_hash"] = hash_admin_password(admin_password)
    _save_inactive(realm, data, "identity")
    return {"generated_password": admin_password if data["admin_password_generated"] else None}


def set_sync_preset(realm: str, preset: str) -> None:
    data = load_realm(realm)
    if not data:
        raise ValueError(f"realm not configured: {realm}")
    presets = {
        "access": {
            "node_role": "access_only",
            "node_storage_profile": "cache_only",
            "sync": {"mode": "lazy", "prefixes": []},
        },
        "shared": {
            "node_role": "shared_storage",
            "node_storage_profile": "limited",
            "sync": {"mode": "active", "prefixes": []},
        },
        "replica": {
            "node_role": "replica_storage",
            "node_storage_profile": "bulk_storage",
            "sync": {"mode": "active", "prefixes": []},
        },
    }
    if preset not in presets:
        raise ValueError(f"unknown sync preset: {preset}")
    data.update(presets[preset])
    _save_inactive(realm, data, "sync")


def set_online_expectation(realm: str, expectation: str) -> None:
    if expectation not in ONLINE_EXPECTATIONS:
        raise ValueError(f"unknown online expectation: {expectation}")
    data = setup_defaults(realm, load_realm(realm))
    data["online_expectation"] = expectation
    data["node_availability"] = ONLINE_EXPECTATIONS[expectation]["node_availability"]
    _save_inactive(realm, data, "availability")


def set_backend_policy(realm: str, policy: str, max_gb: Optional[int] = None) -> None:
    if policy not in BACKEND_POLICIES:
        raise ValueError(f"unknown backend policy: {policy}")
    data = setup_defaults(realm, load_realm(realm))
    preset = BACKEND_POLICIES[policy]
    data["backend_policy"] = policy
    data["node_role"] = preset["node_role"]
    data["node_storage_profile"] = preset["node_storage_profile"]
    data["sync"] = dict(preset["sync"])
    if max_gb is not None:
        data["cache_max_gb"] = int(max_gb)
        data["sync"]["cache_max_bytes"] = int(max_gb) * 1024 * 1024 * 1024
    elif policy != "capped":
        data.pop("cache_max_gb", None)
        data.get("sync", {}).pop("cache_max_bytes", None)
    _save_inactive(realm, data, "storage_policy")


def _parse_rate(value: str) -> int:
    raw = (value or "").strip().lower()
    if not raw:
        return 0
    multiplier = 1
    for suffix, factor in (("kbps", 1024), ("k", 1024), ("mbps", 1024 * 1024),
                           ("m", 1024 * 1024), ("gbps", 1024 * 1024 * 1024),
                           ("g", 1024 * 1024 * 1024)):
        if raw.endswith(suffix):
            multiplier = factor
            raw = raw[:-len(suffix)].strip()
            break
    return int(float(raw) * multiplier)


def set_bandwidth_limits(
    realm: str,
    net_bg: int = 0,
    net_fg: int = 0,
    disk_bg: int = 0,
    disk_fg: int = 0,
) -> None:
    data = setup_defaults(realm, load_realm(realm))
    data["rate_limits"] = {
        "net_bg_bps": int(net_bg),
        "net_fg_bps": int(net_fg),
        "disk_bg_bps": int(disk_bg),
        "disk_fg_bps": int(disk_fg),
    }
    _save_inactive(realm, data, "bandwidth")


def discover_tailscale_peers() -> List[str]:
    try:
        out = subprocess.check_output(
            ["tailscale", "status", "--json"],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        data = json.loads(out)
    except Exception:
        return []
    peers = []
    for peer in (data.get("Peer") or {}).values():
        if not isinstance(peer, dict):
            continue
        ips = peer.get("TailscaleIPs") or []
        if ips:
            peers.append(ips[0])
    return sorted(set(peers))


def dedupe_peer_endpoints(peers: Iterable[str]) -> List[str]:
    out = []
    seen = set()
    for value in peers or []:
        peer = str(value).strip()
        if not peer:
            continue
        key = peer.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(peer)
    return out


def merge_peer_endpoints(existing: Iterable[str], additions: Iterable[str]) -> List[str]:
    return dedupe_peer_endpoints(list(existing or []) + list(additions or []))


@dataclass
class ValidationIssue:
    level: str
    message: str


def validate_realm(realm: str) -> List[ValidationIssue]:
    data = load_realm(realm)
    if not data:
        return [ValidationIssue("error", f"realm config not found: {realm}")]
    issues: List[ValidationIssue] = []
    for key in ("realm", "realm_secret", "mountpoint", "storage_pool"):
        if not data.get(key):
            issues.append(ValidationIssue("error", f"missing required key: {key}"))
    mountpoint = data.get("mountpoint")
    if mountpoint:
        mp = os.path.abspath(os.path.expanduser(mountpoint))
        pool_data = data.get("storage_pool")
        if pool_data:
            pool = StoragePool.from_dict(pool_data)
            for vol in pool.all_volumes:
                try:
                    common = os.path.commonpath([mp, vol.path])
                    if common == mp:
                        issues.append(ValidationIssue("error", f"backend is inside mountpoint: {vol.path}"))
                except ValueError:
                    pass
    try:
        pool = StoragePool.from_dict(data.get("storage_pool"))
        if not pool.primary.is_online():
            issues.append(ValidationIssue("error", f"primary backend is not online: {pool.primary.path}"))
        for vol in pool.secondaries:
            if not vol.is_online():
                issues.append(ValidationIssue("warning", f"secondary backend is offline: {vol.path}"))
    except Exception as e:
        issues.append(ValidationIssue("error", f"invalid storage pool: {e}"))
    if data.get("peer_trust") == "manual" and not data.get("approved_peers"):
        issues.append(ValidationIssue("warning", "manual peer trust has no approved peers"))
    return issues


def activate_realm(realm: str) -> bool:
    issues = validate_realm(realm)
    errors = [i for i in issues if i.level == "error"]
    if errors:
        return False
    data = load_realm(realm)
    state = _ensure_setup_state(data)
    state["activated"] = True
    _mark_step(data, "activated")
    _save_realm_config(realm, data)
    return True


def deactivate_realm(realm: str) -> bool:
    """Mark a realm inactive. launch.sh refuses inactive realms (unless
    --allow-inactive), so this takes it out of service without deleting config."""
    data = load_realm(realm)
    if not data:
        return False
    state = _ensure_setup_state(data)
    state["activated"] = False
    _save_realm_config(realm, data)
    return True


def discover_devices() -> List[dict]:
    try:
        out = subprocess.check_output(
            ["lsblk", "--json", "-o",
             "NAME,TYPE,SIZE,FSTYPE,MOUNTPOINTS,MODEL,TRAN,RM,SERIAL,UUID"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
        data = json.loads(out)
        return data.get("blockdevices", [])
    except Exception:
        return []


def _flatten_mounts(devices: Iterable[dict], parent: str = "") -> List[dict]:
    rows = []
    for dev in devices:
        name = f"{parent}/{dev.get('name')}" if parent else dev.get("name", "")
        mounts = dev.get("mountpoints") or []
        for mount in mounts:
            if mount:
                row = dict(dev)
                row["device"] = name
                row["mountpoint"] = mount
                rows.append(row)
        rows.extend(_flatten_mounts(dev.get("children") or [], name))
    return rows


# lsblk TYPEs that are not real storage the user would target. `loop` covers
# snap/AppImage/flatpak mounts (the usual clutter). Keep disk/part/rom (optical),
# and lvm/crypt/raid mapper devices.
_DEVICE_TYPE_SKIP = {"loop"}


def print_device_summary(show_all: bool = False) -> None:
    rows = _flatten_mounts(discover_devices())
    if not show_all:
        rows = [r for r in rows if (r.get("type") or "") not in _DEVICE_TYPE_SKIP]
    if not rows:
        print("No mounted storage devices found via lsblk.")
        return
    print("Mounted devices:")
    for idx, row in enumerate(rows, start=1):
        model = row.get("model") or ""
        tran = row.get("tran") or ""
        # A stable identifier for the physical/filesystem volume — mount points
        # are NOT reliable across sessions (e.g. an external-disk dock can mount
        # a different disk at the same path). Prefer fs UUID, else disk serial.
        ident = row.get("uuid") or row.get("serial") or ""
        ident_txt = f"  [{ident}]" if ident else ""
        print(f"  {idx}) {row['device']:<14} {row.get('size',''):<8} {tran:<6} "
              f"{model} -> {row['mountpoint']}{ident_txt}")
    if not show_all:
        print("  (loop/snap devices hidden; pass --list-devices-all to show them)")
    print("  Note: mount points can change between sessions; FFSFS identifies a")
    print("  backend by its .ffsfs-volume.id file, not by mount path.")


def _prompt(msg: str, default: Optional[str] = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    value = input(f"{msg}{suffix}: ").strip()
    return value if value else (default or "")


def _yes_no(msg: str, default: bool = False) -> bool:
    d = "Y/n" if default else "y/N"
    value = input(f"{msg} [{d}]: ").strip().lower()
    if not value:
        return default
    return value in ("y", "yes", "1", "true")


def prompt_collaboration(realm: str) -> None:
    """Ask the realm's collaboration intent (recorded, not enforced yet)."""
    data = load_realm(realm) or {}
    current = data.get("collaboration", DEFAULT_COLLABORATION)
    print("Collaboration intent (how this realm is used):")
    print("  solo   - single curator; last-write-wins, conflicts only warned")
    print("  shared - multiple writers; conflicts surfaced (resolution is future)")
    mode = _prompt("Collaboration (solo/shared)", current).lower()
    if mode not in COLLABORATION_MODES:
        print(f"Unknown; keeping '{current}'.")
        mode = current
    set_collaboration(realm, mode)


def _prompt_backend_details(realm: str, path: str, label: str):
    """Ask device class, apply assumption defaults (overridable), optional themed
    job; then register the backend. Returns the created Volume."""
    print("Device class:")
    print("  internal - built-in disk (no size cap, not removable)")
    print("  external - USB/eSATA external HDD/SSD or dock (removable, NO size cap)")
    print("  usb      - small USB flash key (removable, small-file cap)")
    print("  sd       - SD/microSD card (removable, small-file cap)")
    print("  optical  - DVD/Blu-ray (removable, write-once archive)")
    print("  network  - NAS / network share")
    dc = _prompt("Device class", DEVICE_INTERNAL).lower()
    if dc not in DEVICE_CLASSES:
        print("Unknown device class; using 'internal'.")
        dc = DEVICE_INTERNAL
    sugg = suggest_backend_defaults(dc)
    cap = sugg["max_file_size"]
    cap_txt = f"{cap // (1024 * 1024)} MiB" if cap else "unlimited"
    removable = dc in ("usb", "sd", "optical")
    print(f"  assumptions for {dc}: mirror={sugg['mirror']}, "
          f"media={sugg['media'] or '-'}, max file size={cap_txt}"
          f"{', removable' if removable else ''}")
    job_prefix = None
    if _yes_no("Assign a themed job (e.g. 'music only')? Otherwise general backup", False):
        job_prefix = _prompt("Theme vpath prefix (e.g. /music)").strip() or None
    media = _prompt("Media hint (ssd/hdd/network/blank)", sugg["media"] or "")
    if media not in ("", MEDIA_SSD, MEDIA_HDD, MEDIA_NETWORK):
        print("Unknown media hint; leaving blank.")
        media = ""
    mirror = _yes_no("Mirror committed writes to this backend?", sugg["mirror"])
    return add_backend(realm, path, label=label, media=media or None,
                       mirror=mirror, device_class=dc, job_prefix=job_prefix)


def _choose_realm() -> Optional[str]:
    realms = list_realms()
    if realms:
        print("Configured realms:")
        for idx, realm in enumerate(realms, start=1):
            data = load_realm(realm)
            active = bool((data.get("setup_state") or {}).get("activated"))
            print(f"  {idx}) {realm} {'active' if active else 'inactive'}")
        sel = _prompt("Enter a number to edit an existing realm, or a new name to create")
    else:
        sel = _prompt("New realm name")
    if not sel:
        return None
    if sel.isdigit():
        i = int(sel)
        if 1 <= i <= len(realms):
            return realms[i - 1]
        print(f"No realm #{i}.")
        return None
    return sel


def wizard_create_or_edit(realm: str) -> None:
    data = setup_defaults(realm, load_realm(realm))
    if not data.get("realm_secret"):
        print()
        print("Realm setup")
        print("The primary backend holds the realm's metadata and is the default")
        print("write target. It can be a local folder or a path on an external")
        print("disk; additional backends (mirrors/archives) can be added after.")
        mount = _prompt("Mountpoint", os.path.expanduser(f"~/{realm}"))
        base = _prompt("Primary backend folder (local or external path)",
                       os.path.expanduser(f"~/.{realm}/{realm}"))
        join = _prompt("Realm passphrase/key (blank = create new secret)", "")
        secret = None
        passphrase = None
        if join:
            if all(ch in "0123456789abcdefABCDEF" for ch in join) and len(join) >= 32:
                secret = join
            else:
                passphrase = join
        data = create_realm_config(realm, mount, base, passphrase=passphrase, secret=secret)
    else:
        _save_inactive(realm, data)

    print()
    print("Node identity")
    node_name = _prompt("Node name", data.get("node_name") or socket.gethostname())
    host_alias = _prompt("Host alias", data.get("host_alias") or node_name)
    admin_pass = getpass.getpass("Host admin password (blank = auto-generate): ")
    generated = set_node_identity(realm, node_name, host_alias, admin_pass or None).get("generated_password")
    if generated:
        print(f"Generated admin password: {generated}")
        print("Store this password now; only its hash is saved.")

    print()
    prompt_online_expectation(realm)

    print()
    prompt_backend_policy(realm)

    print()
    prompt_collaboration(realm)

    print()
    print_device_summary()
    while _yes_no("Add a secondary backend?", False):
        path = _prompt("Backend folder")
        label = _prompt("Label", os.path.basename(path.rstrip("/")) or "backend")
        try:
            vol = _prompt_backend_details(realm, path, label)
            print(f"Added backend {vol.label}: {vol.path}")
        except Exception as e:
            print(f"Could not add backend: {e}")

    print()
    while _yes_no("Add a seed/known peer?", False):
        peer = _prompt("Peer host, or host:port for a non-default port")
        if peer:
            add_peer(realm, peer, approved=False)

    if _yes_no("Use manual peer approval?", False):
        data = load_realm(realm)
        data["peer_trust"] = "manual"
        _save_inactive(realm, data, "peers")
        while _yes_no("Approve a peer node name?", False):
            peer = _prompt("Peer node name")
            if peer:
                add_peer(realm, peer, approved=True)

    print()
    print_realm_summary(realm)
    issues = validate_realm(realm)
    print_issues(issues)
    if not any(i.level == "error" for i in issues) and _yes_no("Activate this realm?", True):
        activate_realm(realm)
        print()
        print(f"Activated. You can now launch this realm with:")
        print(f"    ./launch.sh {realm}")
        print(f"  (add --bg to run in the background)")
    else:
        print()
        print("Saved as inactive. Activate it later in setup, then launch with:")
        print(f"    ./launch.sh {realm}")


def print_issues(issues: List[ValidationIssue]) -> None:
    if not issues:
        print("Validation: OK")
        return
    print("Validation:")
    for issue in issues:
        print(f"  {issue.level.upper()}: {issue.message}")


def print_realm_summary(realm: str) -> None:
    data = load_realm(realm)
    if not data:
        print(f"Realm not configured: {realm}")
        return
    state = data.get("setup_state") or {}
    print(f"Realm: {realm}")
    print(f"  active: {bool(state.get('activated'))}")
    print(f"  node: {data.get('node_name', '?')} alias={data.get('host_alias', '?')}")
    print(f"  mountpoint: {data.get('mountpoint', '?')}")
    print(f"  peer port: {data.get('port', default_port_for_realm(realm))}")
    print(f"  peer_trust: {data.get('peer_trust', 'realm_secret')}")
    print(f"  trust_unknown_peers: {bool(data.get('trust_unknown_peers', False))}")
    print(f"  known_peers: {len(data.get('known_peers') or [])}")
    print(f"  approved_peers: {len(data.get('approved_peers') or [])}")
    pool_data = data.get("storage_pool")
    if pool_data:
        pool = StoragePool.from_dict(pool_data)
        print("  backends:")
        for vol in pool.all_volumes:
            role = "primary" if vol.vol_id == pool.primary.vol_id else vol.role
            print(f"    - {role}: {vol.label} {vol.path} [{vol.status()}]")


def prompt_identity(realm: str) -> None:
    data = setup_defaults(realm, load_realm(realm))
    print("Node identity")
    node_name = _prompt("Node name", data.get("node_name") or socket.gethostname())
    host_alias = _prompt("Host alias", data.get("host_alias") or node_name)
    admin_pass = getpass.getpass("Host admin password (blank = auto-generate/rotate): ")
    generated = set_node_identity(realm, node_name, host_alias, admin_pass or None).get("generated_password")
    if generated:
        print(f"Generated admin password: {generated}")
        print("Store this password now; only its hash is saved.")


def prompt_add_backend(realm: str) -> None:
    print_device_summary()
    path = _prompt("Backend folder")
    if not path:
        return
    label = _prompt("Label", os.path.basename(path.rstrip("/")) or "backend")
    try:
        vol = _prompt_backend_details(realm, path, label)
        print(f"Added backend {vol.label}: {vol.path}")
    except Exception as e:
        print(f"Could not add backend: {e}")


def prompt_remove_backend(realm: str) -> None:
    print_realm_summary(realm)
    target = _prompt("Backend id, label, or path to remove")
    if not target:
        return
    try:
        vol = remove_backend(realm, target)
        print(f"Removed backend {vol.label}. Files on disk were left untouched.")
    except Exception as e:
        print(f"Could not remove backend: {e}")


def prompt_sync_preset(realm: str) -> None:
    print("Sync preset")
    print("  1) access laptop/cache")
    print("  2) shared workstation/server")
    print("  3) replica/archive node")
    choice = _prompt("Preset", "1")
    preset = {"1": "access", "2": "shared", "3": "replica"}.get(choice, "access")
    set_sync_preset(realm, preset)
    print(f"Set sync preset: {preset}")


def prompt_online_expectation(realm: str) -> None:
    print("How much is this node expected to be online?")
    keys = list(ONLINE_EXPECTATIONS.keys())
    for idx, key in enumerate(keys, start=1):
        print(f"  {idx}) {ONLINE_EXPECTATIONS[key]['label']}")
    choice = _prompt("Choice", "4")
    try:
        key = keys[int(choice) - 1]
    except Exception:
        key = "unknown"
    set_online_expectation(realm, key)
    print(f"Set online expectation: {ONLINE_EXPECTATIONS[key]['label']}")


def prompt_backend_policy(realm: str) -> None:
    print("Backend storage policy")
    keys = list(BACKEND_POLICIES.keys())
    for idx, key in enumerate(keys, start=1):
        print(f"  {idx}) {BACKEND_POLICIES[key]['label']}")
    choice = _prompt("Choice", "3")
    try:
        key = keys[int(choice) - 1]
    except Exception:
        key = "minimal"
    max_gb = None
    if key == "capped":
        raw = _prompt("Maximum local cache GB", "100")
        try:
            max_gb = int(raw)
        except ValueError:
            print("Invalid number; using 100 GB.")
            max_gb = 100
    set_backend_policy(realm, key, max_gb=max_gb)
    print(f"Set backend policy: {BACKEND_POLICIES[key]['label']}")


def prompt_bandwidth(realm: str) -> None:
    print("Bandwidth/rate limits. Blank or 0 means unlimited.")
    net_bg = _parse_rate(_prompt("Background network bytes/sec (e.g. 5m)", "0"))
    net_fg = _parse_rate(_prompt("Foreground network bytes/sec", "0"))
    disk_bg = _parse_rate(_prompt("Background disk bytes/sec", "0"))
    disk_fg = _parse_rate(_prompt("Foreground disk bytes/sec", "0"))
    set_bandwidth_limits(realm, net_bg=net_bg, net_fg=net_fg, disk_bg=disk_bg, disk_fg=disk_fg)
    print("Updated rate limits.")


def prompt_tailscale_seeds(realm: str) -> None:
    peers = discover_tailscale_peers()
    if not peers:
        print("No Tailscale interface peers found. Is tailscale installed and logged in?")
        return
    print("Tailscale interface peers:")
    for idx, peer in enumerate(peers, start=1):
        print(f"  {idx}) {peer}")
    raw = _prompt("Add which peers? numbers, comma-separated, or 'all'", "all")
    selected = peers
    if raw.lower() != "all":
        selected = []
        for part in raw.split(","):
            try:
                selected.append(peers[int(part.strip()) - 1])
            except Exception:
                pass
    data = load_realm(realm)
    default_port = str(data.get("port") or default_port_for_realm(realm))
    port = _prompt("Peer port for selected hosts (blank/that value = realm default)",
                   default_port)
    for host in selected:
        # Store bare host when it's the realm default port, so it stays correct
        # even if the port scheme changes; otherwise pin the explicit port.
        if str(port) == str(default_port_for_realm(realm)):
            add_peer(realm, host, approved=False)
        else:
            add_peer(realm, f"{host}:{port}", approved=False)
    print(f"Added {len(selected)} interface seed host(s); duplicates are ignored.")


def prompt_peer_action(realm: str) -> None:
    print("Peer management")
    print("  1) Add known peer host")
    print("  2) Remove known peer host")
    print("  3) Approve peer node name")
    print("  4) Unapprove peer node name")
    print("  5) Toggle trust_unknown_peers")
    print("  6) Add Tailscale seed hosts")
    choice = _prompt("Choice", "1")
    if choice == "1":
        peer = _prompt("Peer host, or host:port for a non-default port")
        if peer:
            add_peer(realm, peer, approved=False)
    elif choice == "2":
        peer = _prompt("Peer host, or host:port for a non-default port")
        if peer:
            remove_peer(realm, peer, approved=False)
    elif choice == "3":
        peer = _prompt("Peer node name")
        if peer:
            add_peer(realm, peer, approved=True)
    elif choice == "4":
        peer = _prompt("Peer node name")
        if peer:
            remove_peer(realm, peer, approved=True)
    elif choice == "5":
        data = load_realm(realm)
        current = bool(data.get("trust_unknown_peers", False))
        data["trust_unknown_peers"] = _yes_no("Auto-add authenticated unknown peers?", current)
        _save_inactive(realm, data, "peers")
    elif choice == "6":
        prompt_tailscale_seeds(realm)


def _parse_size(s: str, current: Optional[int]) -> Optional[int]:
    """Parse a size string. Blank -> keep current; 'none'/'unlimited'/'0' ->
    None; otherwise an integer with optional K/M/G/T suffix (1024-based)."""
    s = (s or "").strip().lower()
    if s == "":
        return current
    if s in ("none", "unlimited", "0"):
        return None
    m = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([kmgt]?)i?b?", s)
    if not m:
        print("Unrecognized size; keeping current.")
        return current
    mult = {"": 1, "k": 1024, "m": 1024 ** 2, "g": 1024 ** 3, "t": 1024 ** 4}
    return int(float(m.group(1)) * mult[m.group(2)])


def prompt_edit_backend(realm: str) -> None:
    """List the realm's backends and edit one's fields (role, mirror, media,
    size caps, device class, themed job)."""
    data = load_realm(realm)
    if not data:
        print("Realm not configured.")
        return
    pool = StoragePool.from_dict(
        data.get("storage_pool") or StoragePool.single(data.get("base")).to_dict())
    vols = pool.all_volumes
    if not vols:
        print("No backends configured.")
        return
    print("Backends:")
    for i, v in enumerate(vols, start=1):
        role = "primary" if v is pool.primary else v.role
        cap = f"{v.max_file_size}B" if v.max_file_size else "unlimited"
        print(f"  {i}) {v.label} [{role}] {v.path}")
        print(f"       mirror={'yes' if v.mirror else 'no'} media={v.media or '-'} "
              f"device={v.device_class or '-'} max_file_size={cap} "
              f"job={v.job_prefix or v.job or '-'}")
    sel = _prompt("Backend number to edit (blank to cancel)")
    if not sel.isdigit() or not (1 <= int(sel) <= len(vols)):
        print("Cancelled.")
        return
    v = vols[int(sel) - 1]
    print("(blank = keep current)")

    role_in = _prompt(f"Role archive/cache (current: {v.role})", "")
    if role_in:
        v.role = role_in
    media_in = _prompt(f"Media ssd/hdd/network (current: {v.media or 'none'})", "")
    if media_in:
        if media_in in (MEDIA_SSD, MEDIA_HDD, MEDIA_NETWORK):
            v.media = media_in
        else:
            print("Unknown media; keeping.")
    v.mirror = _yes_no("Mirror committed writes to this backend?", v.mirror)
    v.max_file_size = _parse_size(
        _prompt(f"Max file size, e.g. 2G ('none'=unlimited) (current: {v.max_file_size or 'unlimited'})", ""),
        v.max_file_size)
    v.max_bytes = _parse_size(
        _prompt(f"Max total bytes ('none'=unlimited) (current: {v.max_bytes or 'unlimited'})", ""),
        v.max_bytes)
    v.reserve_bytes = _parse_size(
        _prompt(f"Reserve free bytes ('none'=clear) (current: {v.reserve_bytes or 'none'})", ""),
        v.reserve_bytes)
    dc_in = _prompt(f"Device class (current: {v.device_class or 'none'})", "")
    if dc_in:
        if dc_in in DEVICE_CLASSES:
            v.device_class = dc_in
        else:
            print("Unknown device class; keeping.")
    job_in = _prompt(f"Themed job prefix e.g. /music ('none'=clear) (current: {v.job_prefix or 'general'})", "")
    if job_in.lower() == "none":
        v.job_prefix = None
        v.job = JOB_GENERAL
    elif job_in:
        v.job_prefix = job_in
        v.job = job_in

    data["storage_pool"] = pool.to_dict()
    _save_inactive(realm, data, "backends")
    print(f"Updated backend {v.label}.")


def edit_realm_menu(realm: str) -> None:
    if not load_realm(realm):
        wizard_create_or_edit(realm)
        return
    while True:
        print()
        print_realm_summary(realm)
        print()
        print("1) Edit identity/admin password")
        print("2) Set online expectation")
        print("3) Set node sync/storage policy   (node role + sync mode, not a single backend)")
        print("4) Add a backend")
        print("5) Edit a backend                 (role, mirror, media, size caps, device, job)")
        print("6) Remove a backend")
        print("7) Manage peers")
        print("8) Set sync preset")
        print("9) Set bandwidth/rate limits")
        print("10) Validate           (check the config is complete and consistent)")
        print("11) Activate           (mark ready to launch — required before deploy)")
        print("12) Deactivate         (take out of service; launch.sh refuses it)")
        print("13) Set collaboration intent (solo/shared)")
        print("14) Set realm secret   (align/join peers; use same on every host)")
        print("0) Back")
        choice = _prompt("Choice", "10")
        if choice == "1":
            prompt_identity(realm)
        elif choice == "2":
            prompt_online_expectation(realm)
        elif choice == "3":
            prompt_backend_policy(realm)
        elif choice == "4":
            prompt_add_backend(realm)
        elif choice == "5":
            prompt_edit_backend(realm)
        elif choice == "6":
            prompt_remove_backend(realm)
        elif choice == "7":
            prompt_peer_action(realm)
        elif choice == "8":
            prompt_sync_preset(realm)
        elif choice == "9":
            prompt_bandwidth(realm)
        elif choice == "10":
            print_issues(validate_realm(realm))
        elif choice == "11":
            print_issues(validate_realm(realm))
            if activate_realm(realm):
                print("Activated. launch.sh will now run this realm.")
            else:
                print("Not activated — fix the errors above first.")
        elif choice == "12":
            if deactivate_realm(realm):
                print("Deactivated. launch.sh refuses it unless --allow-inactive.")
            else:
                print("Could not deactivate (realm not found).")
        elif choice == "13":
            prompt_collaboration(realm)
        elif choice == "14":
            prompt_realm_secret(realm)
        elif choice == "0":
            return
        else:
            print("Invalid choice")


def _print_realm_intro() -> None:
    print("A 'realm' is an isolated FFSFS namespace — a named, self-contained")
    print("filesystem with its own storage and peer group. Think of it as a")
    print("separate vault / share / workspace / 'drive'. Peers only sync with")
    print("each other inside the same realm (same name + shared secret), and you")
    print("can run several independent realms on one host.")
    print()


def print_realms() -> None:
    realms = list_realms()
    if not realms:
        print("No realms configured yet. Choose 'Create / edit a realm' to make one.")
        return
    print("Configured realms:")
    for name in realms:
        data = load_realm(name) or {}
        state = (data.get("setup_state") or {})
        active = "active" if state.get("activated") else "inactive"
        mount = data.get("mountpoint", "?")
        print(f"  - {name:<20} [{active}]  mount: {mount}")


def interactive_main(args) -> int:
    print("FFSFS setup")
    print()
    _print_realm_intro()
    while True:
        print("1) Create / edit a realm")
        print("2) Show a realm's configuration")
        print("3) List realms")
        print("4) Validate a realm        (check the config is complete and consistent)")
        print("5) Activate a realm        (mark ready to launch — required before deploy)")
        print("6) Deactivate a realm      (take out of service; launch.sh then refuses it)")
        print("7) List devices            (mounted storage; loop/snap hidden)")
        print("0) Exit")
        choice = _prompt("Choice", "1")
        if choice == "1":
            realm = args.realm or _choose_realm()
            if realm:
                edit_realm_menu(realm)
        elif choice == "2":
            realm = args.realm or _choose_realm()
            if realm:
                print_realm_summary(realm)
        elif choice == "3":
            print_realms()
        elif choice == "4":
            realm = args.realm or _choose_realm()
            if realm:
                print_issues(validate_realm(realm))
        elif choice == "5":
            realm = args.realm or _choose_realm()
            if realm:
                print_issues(validate_realm(realm))
                if activate_realm(realm):
                    print(f"Activated '{realm}'. launch.sh will now run it.")
                else:
                    print("Not activated — fix the errors above first.")
        elif choice == "6":
            realm = args.realm or _choose_realm()
            if realm:
                if deactivate_realm(realm):
                    print(f"Deactivated '{realm}'. launch.sh will refuse it "
                          f"unless --allow-inactive is passed.")
                else:
                    print("Could not deactivate (realm not found).")
        elif choice == "7":
            print_device_summary()
        elif choice == "0":
            return 0
        else:
            print("Invalid choice")
        print()


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="FFSFS console setup app")
    parser.add_argument("--realm", help="realm to edit/check")
    parser.add_argument("--check", action="store_true", help="validate configured realms and exit")
    parser.add_argument("--activate", action="store_true", help="validate and activate --realm")
    parser.add_argument("--deactivate", action="store_true", help="deactivate --realm (take out of service)")
    parser.add_argument("--set-realm-secret", metavar="PASSPHRASE_OR_HEX", default=None,
                        help="set --realm's secret from a shared passphrase or exact hex (same on every host)")
    parser.add_argument("--show-realm-secret", action="store_true", help="print --realm's current realm secret and exit")
    parser.add_argument("--list-devices", action="store_true", help="list mounted storage devices and exit")
    parser.add_argument("--list-devices-all", action="store_true", help="like --list-devices but include loop/snap devices")
    parser.add_argument("--list-realms", action="store_true", help="list configured realms and exit")
    args = parser.parse_args(argv)

    if args.list_devices or args.list_devices_all:
        print_device_summary(show_all=args.list_devices_all)
        return 0
    if args.list_realms:
        print_realms()
        return 0
    if args.show_realm_secret:
        if not args.realm:
            print("--show-realm-secret requires --realm", file=sys.stderr)
            return 2
        print((load_realm(args.realm) or {}).get("realm_secret") or "")
        return 0
    if args.set_realm_secret is not None:
        if not args.realm:
            print("--set-realm-secret requires --realm", file=sys.stderr)
            return 2
        v = args.set_realm_secret
        is_hex = len(v) >= 32 and all(c in "0123456789abcdefABCDEF" for c in v)
        try:
            set_realm_secret(args.realm, secret=v if is_hex else None,
                             passphrase=None if is_hex else v)
            print("Realm secret updated. Restart the service; use the same on every host.")
            return 0
        except Exception as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
    if args.deactivate:
        if not args.realm:
            print("--deactivate requires --realm", file=sys.stderr)
            return 2
        if deactivate_realm(args.realm):
            print(f"Deactivated '{args.realm}'.")
            return 0
        print("Not found.")
        return 1
    if args.check:
        realms = [args.realm] if args.realm else list_realms()
        if not realms:
            print("No realms configured.")
            return 1
        failed = False
        for realm in realms:
            print_realm_summary(realm)
            issues = validate_realm(realm)
            print_issues(issues)
            failed = failed or any(i.level == "error" for i in issues)
        return 1 if failed else 0
    if args.activate:
        if not args.realm:
            print("--activate requires --realm", file=sys.stderr)
            return 2
        print_issues(validate_realm(args.realm))
        if activate_realm(args.realm):
            print("Activated.")
            return 0
        print("Not activated.")
        return 1
    return interactive_main(args)


if __name__ == "__main__":
    raise SystemExit(main())
