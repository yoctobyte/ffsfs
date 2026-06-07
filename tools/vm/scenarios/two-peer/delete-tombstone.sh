#!/usr/bin/env bash
set -euo pipefail

two_peer_healthz_cross_check

create_file_a='
set -euo pipefail
cd /home/'"$FFSFS_VM_USER"'/work/ffsfs
PYTHONPATH=/home/'"$FFSFS_VM_USER"'/work/ffsfs python3 - <<PY
import time
from ffsfs import StorageBackend

backend = StorageBackend("'"$peer_a_data_base"'", "'"$realm"'")
temp = backend.create_temp_for("shared/hello.txt")
with open(temp, "wb") as f:
    f.write(b"hello from peer a")
final = backend.commit_temp("shared/hello.txt", temp, "write")
print("created:", final)
PY
'
two_peer_run_a "$create_file_a" | tee "$log_dir/$name_a.create-file.log"

sleep 1

verify_visible_b='
set -euo pipefail
python3 - <<PY
import json
import urllib.parse
import urllib.request

base = "http://127.0.0.1:'"$peer_a_port"'"
realm = "'"$realm"'"

def get_json(path, **params):
    qs = urllib.parse.urlencode(params)
    with urllib.request.urlopen(f"{base}{path}?{qs}", timeout=10) as resp:
        return json.load(resp)

listing = get_json("/list-dir", realm=realm, dir="shared")
assert "hello.txt" in listing["files"], f"hello.txt not in listing: {listing}"

head = get_json("/head", realm=realm, vpath="shared/hello.txt")
assert head["version"]["name"].startswith("hello.txt."), head
assert not head.get("deleted"), f"file should not be deleted: {head}"

print("peer-b sees hello.txt (visible, not deleted)")
PY
'
two_peer_run_b "$verify_visible_b" | tee "$log_dir/$name_b.verify-visible.log"

delete_file_a='
set -euo pipefail
cd /home/'"$FFSFS_VM_USER"'/work/ffsfs
PYTHONPATH=/home/'"$FFSFS_VM_USER"'/work/ffsfs python3 - <<PY
from ffsfs import StorageBackend

backend = StorageBackend("'"$peer_a_data_base"'", "'"$realm"'")
final = backend.commit_delete("shared/hello.txt")
print("deleted:", final)
PY
'
two_peer_run_a "$delete_file_a" | tee "$log_dir/$name_a.delete-file.log"

sleep 1

verify_deleted_b='
set -euo pipefail
python3 - <<PY
import json
import urllib.parse
import urllib.request

base = "http://127.0.0.1:'"$peer_a_port"'"
realm = "'"$realm"'"

def get_json(path, **params):
    qs = urllib.parse.urlencode(params)
    with urllib.request.urlopen(f"{base}{path}?{qs}", timeout=10) as resp:
        return json.load(resp)

listing = get_json("/list-dir", realm=realm, dir="shared")
assert "hello.txt" not in listing["files"], f"hello.txt should be hidden: {listing}"

head = get_json("/head", realm=realm, vpath="shared/hello.txt")
assert head.get("deleted"), f"file should be deleted: {head}"
assert head["version"]["mode"] == "delete", head

print("peer-b confirms hello.txt is deleted")
PY
'
two_peer_run_b "$verify_deleted_b" | tee "$log_dir/$name_b.verify-deleted.log"

recreate_file_a='
set -euo pipefail
cd /home/'"$FFSFS_VM_USER"'/work/ffsfs
PYTHONPATH=/home/'"$FFSFS_VM_USER"'/work/ffsfs python3 - <<PY
from ffsfs import StorageBackend

backend = StorageBackend("'"$peer_a_data_base"'", "'"$realm"'")
temp = backend.create_temp_for("shared/hello.txt")
with open(temp, "wb") as f:
    f.write(b"hello again")
final = backend.commit_temp("shared/hello.txt", temp, "write")
print("recreated:", final)
PY
'
two_peer_run_a "$recreate_file_a" | tee "$log_dir/$name_a.recreate-file.log"

sleep 1

verify_recreated_b='
set -euo pipefail
python3 - <<PY
import json
import urllib.parse
import urllib.request

base = "http://127.0.0.1:'"$peer_a_port"'"
realm = "'"$realm"'"

def get_json(path, **params):
    qs = urllib.parse.urlencode(params)
    with urllib.request.urlopen(f"{base}{path}?{qs}", timeout=10) as resp:
        return json.load(resp)

listing = get_json("/list-dir", realm=realm, dir="shared")
assert "hello.txt" in listing["files"], f"hello.txt should be visible again: {listing}"

head = get_json("/head", realm=realm, vpath="shared/hello.txt")
assert not head.get("deleted"), f"file should not be deleted after recreate: {head}"
assert head["version"]["mode"] == "write", head

version = head["version"]["name"]
vpath = "shared/" + version
qs = urllib.parse.urlencode({"realm": realm, "vpath": vpath})
with urllib.request.urlopen(f"{base}/get-file?{qs}", timeout=10) as resp:
    body = resp.read()
assert body == b"hello again", body

print("peer-b fetched recreated file:", body.decode())
PY
'
two_peer_run_b "$verify_recreated_b" | tee "$log_dir/$name_b.verify-recreated.log"
