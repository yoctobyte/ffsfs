#!/usr/bin/env bash
# pool-read-write.sh — Peer A writes to a multi-backend pool, Peer B fetches via API
set -euo pipefail

two_peer_healthz_cross_check
two_peer_link

# Peer A: set up a pool with primary = peer's own data base, secondary = extra volume
# This way the peer server sees the files via its registered data_path.
pool_setup_a='
set -euo pipefail
cd /home/'"$FFSFS_VM_USER"'/work/ffsfs
PYTHONPATH=/home/'"$FFSFS_VM_USER"'/work/ffsfs python3 - <<PY
import os, shutil
from ffsfs import StorageBackend
from ffsvolumes import Volume, StoragePool

# Use peer'"'"'s own data base as pool primary so the running peer server sees files
primary_path = "'"$peer_a_data_base"'"
secondary_path = "/tmp/ffsfs-pool-secondary"

# Clean up secondary from prior runs
if os.path.exists(secondary_path):
    shutil.rmtree(secondary_path)

vol1 = Volume(primary_path, role="primary", label="ssd-primary")
# Only init if no volume ID exists yet (peer server already created the dir)
if not os.path.exists(os.path.join(primary_path, ".ffsfs-volume.id")):
    vol1.init()

vol2 = Volume(secondary_path, role="archive", label="hdd-archive", mirror=True)
vol2.init()

pool = StoragePool(primary=vol1, secondaries=[vol2])
backend = StorageBackend(primary_path, "'"$realm"'", pool=pool)

# Write two files to the pool
temp = backend.create_temp_for("shared/pool-file.txt")
with open(temp, "wb") as f:
    f.write(b"data written to pool")
final = backend.commit_temp("shared/pool-file.txt", temp, "write")
print(f"pool write 1: {final}")
mirrored = os.path.join(secondary_path, ".ffsfs_data", "shared", os.path.basename(final))
assert os.path.exists(mirrored), f"mirror missing: {mirrored}"
assert open(mirrored, "rb").read() == b"data written to pool"
print(f"pool mirror 1: {mirrored}")

temp2 = backend.create_temp_for("shared/another.txt")
with open(temp2, "wb") as f:
    f.write(b"second pool file")
final2 = backend.commit_temp("shared/another.txt", temp2, "write")
print(f"pool write 2: {final2}")
mirrored2 = os.path.join(secondary_path, ".ffsfs_data", "shared", os.path.basename(final2))
assert os.path.exists(mirrored2), f"mirror missing: {mirrored2}"
assert open(mirrored2, "rb").read() == b"second pool file"
print(f"pool mirror 2: {mirrored2}")

# Verify pool reads scan all backends
latest = backend.pick_latest("shared/pool-file.txt")
assert latest is not None
with open(latest, "rb") as f:
    assert f.read() == b"data written to pool"
print("pool read OK")

# Verify volume status tracking
assert vol1.is_online()
assert vol2.is_online()
print("both volumes online")
PY
'
two_peer_run_a "$pool_setup_a" | tee "$log_dir/$name_a.pool-setup.log"

# Peer B: fetch both files from Peer A via the peer API
fetch_check_b='
python3 - <<PY
import json
import urllib.parse
import urllib.request

base = "http://10.0.2.2:'"$peer_a_host_port"'"
realm = "'"$realm"'"

def get_json(path, **params):
    qs = urllib.parse.urlencode(params)
    with urllib.request.urlopen(f"{base}{path}?{qs}", timeout=10) as resp:
        return json.load(resp)

# Check listing
listing = get_json("/list-dir", realm=realm, dir="shared")
files = sorted(listing["files"])
assert "pool-file.txt" in files, f"pool-file.txt missing from listing: {files}"
assert "another.txt" in files, f"another.txt missing from listing: {files}"
print("listing OK:", files)

# Check head for pool-file.txt
head = get_json("/head", realm=realm, vpath="shared/pool-file.txt")
version = head["version"]["name"]
assert version.startswith("pool-file.txt."), head
assert not head.get("deleted"), head
print("head OK:", version)

# Fetch content
vpath = "shared/" + version
qs = urllib.parse.urlencode({"realm": realm, "vpath": vpath})
with urllib.request.urlopen(f"{base}/get-file?{qs}", timeout=10) as resp:
    body = resp.read()
assert body == b"data written to pool", body
print("fetch OK: pool-file.txt =", body.decode())

# Check head and fetch for another.txt
head2 = get_json("/head", realm=realm, vpath="shared/another.txt")
version2 = head2["version"]["name"]
vpath2 = "shared/" + version2
qs2 = urllib.parse.urlencode({"realm": realm, "vpath": vpath2})
with urllib.request.urlopen(f"{base}/get-file?{qs2}", timeout=10) as resp:
    body2 = resp.read()
assert body2 == b"second pool file", body2
print("fetch OK: another.txt =", body2.decode())
PY
'
two_peer_run_b "$fetch_check_b" | tee "$log_dir/$name_b.fetch-check.log"

echo "pool-read-write scenario PASSED"
