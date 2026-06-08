import hashlib
import os
import stat

import pytest

import ffspeers
import ffssetup
from ffsctl import _realm_config_path
from ffsutils import HASH_BASE32_LEN, base32_crockford


def _crockford_hash(data: bytes, length: int = HASH_BASE32_LEN) -> str:
    digest = hashlib.sha256(data).digest()
    return base32_crockford(int.from_bytes(digest, "big"))[:length]


@pytest.mark.unit
def test_content_hash_matches_crockford(tmp_path):
    data = b"hello ffsfs integrity"
    p = tmp_path / "f.bin"
    p.write_bytes(data)
    assert ffspeers._content_hash_matches(str(p), _crockford_hash(data)) is True


@pytest.mark.unit
def test_content_hash_matches_legacy_hex(tmp_path):
    data = b"legacy payload"
    p = tmp_path / "f.bin"
    p.write_bytes(data)
    assert ffspeers._content_hash_matches(str(p), hashlib.sha256(data).hexdigest()) is True


@pytest.mark.unit
def test_content_hash_mismatch_rejected(tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(b"actual bytes")
    # hash computed over different content
    wrong = _crockford_hash(b"some other content")
    assert ffspeers._content_hash_matches(str(p), wrong) is False


@pytest.mark.unit
def test_content_hash_truncated_transfer_rejected(tmp_path):
    full = b"a" * 4096
    expected = _crockford_hash(full)
    p = tmp_path / "f.bin"
    p.write_bytes(full[:2048])  # simulate truncation
    assert ffspeers._content_hash_matches(str(p), expected) is False


@pytest.mark.unit
def test_content_hash_null_hash_skips_verification(tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(b"whatever")
    assert ffspeers._content_hash_matches(str(p), "NULL_HASH") is True
    assert ffspeers._content_hash_matches(str(p), "") is True


@pytest.mark.unit
def test_peer_app_has_request_body_limit():
    assert ffspeers.app.config.get("MAX_CONTENT_LENGTH") == 16 * 1024 * 1024


@pytest.mark.unit
def test_realm_config_written_owner_only(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    ffssetup.create_realm_config(
        "secperm",
        str(tmp_path / "mnt"),
        str(tmp_path / "store"),
        passphrase="a strong realm passphrase",
    )
    cfg_path = _realm_config_path("secperm")
    assert os.path.exists(cfg_path)
    mode = stat.S_IMODE(os.stat(cfg_path).st_mode)
    assert mode == 0o600, f"realm config perms are {oct(mode)}, expected 0o600"
    # secret must actually be present (so the perm guarantee is meaningful)
    import json
    with open(cfg_path) as f:
        assert json.load(f).get("realm_secret")
