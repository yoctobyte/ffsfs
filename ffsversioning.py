"""Versioning policy — how much history a path is allowed to keep.

Phase 1 of agents/workload_modes_design.md §4. FFSFS has exactly one storage
model (an immutable version per close) and no per-path way out, which is fine
for an archive drive and wrong for a live working set: a 904-byte node-status
heartbeat produced 324 permanent versions in two days on the `testff` realm.

This module adds the missing axis. It is deliberately shaped like the
redundancy-class resolver in `ffsredundancy.py` (same config block layout,
same longest-prefix-wins resolution) so operators learn one pattern and the
two axes stay independent:

    redundancy  — how many copies exist, across nodes      ("rf:2")
    versioning  — how much history one node keeps          ("latest:3")

Realm config block:

    "versioning": {"default": "versioned",
                   "overrides": {"var/db": "latest:3"}}

Policies:

    versioned   keep every committed version (default; today's behaviour)
    latest:N    keep the N newest versions of a logical name, drop the rest
    scratch     not versioned at all — Phase 2, rejected until implemented

`latest:N` is a deliberate, operator-declared exception to "never auto-delete
history", so every removal is logged and the selection logic below refuses to
drop the version a reader would currently see.
"""

from typing import Iterable, List, Optional, Sequence

import os

import ffslog
from ffsutils import NODE_STATUS_DIR, is_hidden_mode, parse_versioned_filename

# ---- policy model -----------------------------------------------------------

POLICY_VERSIONED = "versioned"
POLICY_SCRATCH = "scratch"
POLICY_LATEST_PREFIX = "latest:"

DEFAULT_POLICY = POLICY_VERSIONED

# Applied unless the operator configures the same prefix explicitly. The
# node-status dir is disposable metadata republished every few minutes; keeping
# its history was never intended. This replaces the hardcoded special-case
# pruner that used to live in FFSFS._prune_node_status().
BUILTIN_OVERRIDES = {NODE_STATUS_DIR: f"{POLICY_LATEST_PREFIX}1"}


def parse_latest(spec: str) -> Optional[int]:
    """Return N for a "latest:N" policy, else None."""
    if isinstance(spec, str) and spec.startswith(POLICY_LATEST_PREFIX):
        try:
            return int(spec[len(POLICY_LATEST_PREFIX):])
        except ValueError:
            return None
    return None


def normalize_policy(spec: str) -> str:
    """Validate and canonicalize a versioning-policy string.

    Accepts "versioned" and "latest:N" (N>=1). Raises ValueError otherwise —
    including for "scratch", which is designed but not built. Accepting a
    policy that silently does nothing is the failure mode this whole area is
    trying to escape.
    """
    if not isinstance(spec, str):
        raise ValueError(
            f"versioning policy must be a string, got {type(spec).__name__}")
    s = spec.strip().lower()
    if s == POLICY_VERSIONED:
        return s
    if s == POLICY_SCRATCH:
        raise ValueError(
            "versioning policy 'scratch' is designed but not implemented "
            "(Phase 2 of agents/workload_modes_design.md); it is rejected "
            "rather than silently ignored")
    n = parse_latest(s)
    if n is not None:
        if n < 1:
            raise ValueError(
                f"latest:N must keep at least one version: {spec!r}")
        return f"{POLICY_LATEST_PREFIX}{n}"
    raise ValueError(f"unknown versioning policy: {spec!r}")


def keep_count(policy: str) -> Optional[int]:
    """Versions to retain, or None for "keep everything"."""
    return parse_latest(policy)


# ---- per-realm / per-prefix config ------------------------------------------

def _norm_prefix(prefix: str) -> str:
    return (prefix or "").strip().strip("/")


def normalize_versioning_config(cfg: Optional[dict]) -> dict:
    """Validate + canonicalize a versioning config block.

    Returns {"default": <policy>, "overrides": {prefix: policy}}. Built-in
    overrides are merged in first so an operator can override them but does not
    have to restate them.
    """
    cfg = cfg or {}
    default = normalize_policy(cfg.get("default", DEFAULT_POLICY))
    overrides = {
        _norm_prefix(p): normalize_policy(s)
        for p, s in BUILTIN_OVERRIDES.items()
    }
    for prefix, spec in (cfg.get("overrides") or {}).items():
        overrides[_norm_prefix(prefix)] = normalize_policy(spec)
    return {"default": default, "overrides": overrides}


def policy_for_path(vpath: str, cfg: Optional[dict]) -> str:
    """Resolve the effective versioning policy for a vpath.

    Longest matching prefix override wins; otherwise the configured default.
    Mirrors ffsredundancy.class_for_path so the two axes resolve identically.
    """
    return resolve(vpath, normalize_versioning_config(cfg))


def resolve(vpath: str, norm: dict) -> str:
    """policy_for_path against an ALREADY-normalized config.

    The commit path resolves a policy for every write, so it normalizes once at
    startup and calls this instead of re-validating the config per file.
    """
    vp = _norm_prefix(vpath)
    best_prefix, best_policy = None, norm["default"]
    for prefix, policy in norm["overrides"].items():
        if vp == prefix or (prefix and vp.startswith(prefix + "/")):
            if best_prefix is None or len(prefix) > len(best_prefix):
                best_prefix, best_policy = prefix, policy
    return best_policy


# ---- retention --------------------------------------------------------------
# Safety-critical: this deletes committed history. The ordering below MUST match
# latest_version_path()/pick_latest() — (timestamp, mtime_ns, path) descending —
# or retention could remove the very version a reader currently sees.

def _sort_key(entry) -> tuple:
    ts, mtime_ns, path = entry[0], entry[1], entry[2]
    return (ts, mtime_ns, path)


def collect_versions(dirpath: str, logical_name: str) -> List[tuple]:
    """Return [(ts, mtime_ns, path, is_marker)] for committed versions.

    `is_marker` is True for hidden-mode versions — delete tombstones and `moved`
    markers. They carry no content (they are zero-byte) and are counted
    separately by select_prunable, because a tombstone must never be allowed to
    displace the bytes it hides.

    In-flight temps (.NULL_HASH.) and unparseable names are skipped: retention
    never touches a file it cannot positively identify as a committed version of
    this logical name.
    """
    out: List[tuple] = []
    try:
        with os.scandir(dirpath) as it:
            for de in it:
                if not de.is_file():
                    continue
                parsed = parse_versioned_filename(de.name)
                if not parsed or parsed.get("logical_name") != logical_name:
                    continue
                try:
                    ts = int(parsed["timestamp"])
                except (KeyError, TypeError, ValueError):
                    continue
                try:
                    mtime_ns = de.stat().st_mtime_ns
                except OSError:
                    mtime_ns = 0
                out.append((ts, mtime_ns, de.path,
                            bool(is_hidden_mode(parsed.get("mode")))))
    except (FileNotFoundError, NotADirectoryError):
        return []
    except OSError as e:
        ffslog.warn(f"retention: cannot scan {dirpath}: {e}")
        return []
    return out


def select_prunable(versions: Sequence[tuple], keep: int,
                    protect: Iterable[str] = ()) -> List[str]:
    """Choose which committed versions to drop, newest-first ordering.

    Content-bearing versions and hidden-mode markers (delete tombstones, `moved`
    markers) are counted SEPARATELY, each keeping its own newest `keep`.

    That separation is the safety property. Counted together, a delete tombstone
    is the newest version of a logical file, so `latest:1` + delete left nothing
    but a zero-byte tombstone — every byte reclaimed the instant a user pressed
    delete, on every node that saw the tombstone. Retention bounds HISTORY. It
    must never be the mechanism that destroys the last copy of the content, and
    a deleted file is exactly when a user is most likely to want it back.

    Reclaiming bytes behind a tombstone is a separate, local, resource-driven
    decision with a grace period — see agents/data_lifecycle_design.md — not
    something a propagated delete may trigger.

    Never returns the newest `keep` of either class, never returns anything in
    `protect`, and returns nothing when `keep` < 1.
    """
    if keep is None or keep < 1:
        return []
    protected = set(protect)
    content, markers = [], []
    for entry in versions:
        (markers if (len(entry) > 3 and entry[3]) else content).append(entry)
    out = []
    for group in (content, markers):
        ordered = sorted(group, key=_sort_key, reverse=True)
        out.extend(e[2] for e in ordered[keep:] if e[2] not in protected)
    return out


def apply_retention(dirpath: str, logical_name: str, keep: Optional[int],
                    protect: Iterable[str] = ()) -> List[str]:
    """Enforce `latest:keep` for one logical name in one directory.

    Returns the paths actually removed. Removal failures are logged and skipped
    rather than raised: retention is housekeeping and must never fail the commit
    that triggered it.
    """
    if keep is None or keep < 1:
        return []
    versions = collect_versions(dirpath, logical_name)
    if len(versions) <= keep:
        return []
    # NB: cannot early-return on total count alone beyond this cheap case —
    # content and markers are bounded separately below.
    removed: List[str] = []
    for path in select_prunable(versions, keep, protect):
        try:
            os.remove(path)
            removed.append(path)
        except FileNotFoundError:
            pass
        except OSError as e:
            ffslog.warn(f"retention: could not remove {path}: {e}")
    if removed:
        # Auto-deleting history is an operator-declared exception, so say so.
        ffslog.info(
            f"retention: kept newest {keep} of {logical_name!r} in {dirpath}, "
            f"dropped {len(removed)}")
    return removed


def bounded_prefixes(norm: dict) -> List[str]:
    """Prefixes whose policy keeps only N versions. Empty list means nothing to
    sweep (everything is `versioned`)."""
    return [p for p, policy in (norm.get("overrides") or {}).items()
            if keep_count(policy) is not None]


def sweep(data_roots: Iterable[str], norm: dict) -> int:
    """Enforce bounded policies across the stored tree; return versions removed.

    The commit hook only sees writes made through this node. Versions arriving
    from a peer land on disk via the sync worker and would otherwise never be
    subject to retention, so a periodic sweep is what makes the policy true
    rather than merely usually-true.

    Cost is scoped to what the policy actually bounds: only subtrees under a
    `latest:N` prefix are walked. With the default config that is just
    `.ffsfs-nodes`. A realm whose *default* is bounded walks the whole tree —
    that is the operator's explicit choice.
    """
    if keep_count(norm.get("default", DEFAULT_POLICY)) is not None:
        subtrees = [""]                      # default is bounded: whole tree
    else:
        subtrees = bounded_prefixes(norm)
    if not subtrees:
        return 0

    removed = 0
    for root in data_roots:
        for prefix in subtrees:
            start = os.path.join(root, prefix) if prefix else root
            if not os.path.isdir(start):
                continue
            for dirpath, _dirnames, filenames in os.walk(start):
                rel = os.path.relpath(dirpath, root)
                vdir = "" if rel == "." else rel
                logical_names = set()
                for fn in filenames:
                    parsed = parse_versioned_filename(fn)
                    if parsed and parsed.get("logical_name"):
                        logical_names.add(parsed["logical_name"])
                for ln in logical_names:
                    vpath = f"{vdir}/{ln}" if vdir else ln
                    keep = keep_count(resolve(vpath, norm))
                    if keep is None:
                        continue
                    removed += len(apply_retention(dirpath, ln, keep))
    return removed
