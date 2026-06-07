import time
import pytest
from unittest.mock import patch

from ffspeer_auth import (
    generate_realm_secret,
    canonical_string,
    sign_request,
    NonceCache,
    RequestVerifier,
    HEADER_SIGNATURE,
    HEADER_NONCE,
    HEADER_TIMESTAMP,
    HEADER_REALM,
    HEADER_NODE,
)


@pytest.mark.unit
class TestGenerateSecret:
    def test_length(self):
        s = generate_realm_secret()
        assert len(s) == 64  # 32 bytes hex

    def test_uniqueness(self):
        a = generate_realm_secret()
        b = generate_realm_secret()
        assert a != b


@pytest.mark.unit
class TestCanonicalString:
    def test_basic(self):
        c = canonical_string("GET", "/list-files", {"realm": "test", "prefix": ""},
                             "1000000", "abc123", b"")
        lines = c.split("\n")
        assert lines[0] == "GET"
        assert lines[1] == "/list-files"
        assert "prefix=" in lines[2]
        assert "realm=test" in lines[2]
        assert lines[3] == "1000000"
        assert lines[4] == "abc123"

    def test_params_sorted(self):
        c1 = canonical_string("POST", "/notify", {"b": "2", "a": "1"},
                              "100", "n", b"body")
        c2 = canonical_string("POST", "/notify", {"a": "1", "b": "2"},
                              "100", "n", b"body")
        assert c1 == c2

    def test_method_uppercased(self):
        c = canonical_string("get", "/hello", {}, "0", "n", b"")
        assert c.startswith("GET\n")

    def test_body_hash_differs(self):
        c1 = canonical_string("POST", "/x", {}, "0", "n", b"hello")
        c2 = canonical_string("POST", "/x", {}, "0", "n", b"world")
        assert c1 != c2

    def test_empty_params(self):
        c = canonical_string("GET", "/healthz", {}, "0", "n", b"")
        lines = c.split("\n")
        assert lines[2] == ""


@pytest.mark.unit
class TestSignAndVerify:
    def test_roundtrip(self):
        secret = generate_realm_secret()
        headers = sign_request(secret, "GET", "/list-files",
                               {"realm": "myrealm"}, b"", "myrealm", "node-a")
        v = RequestVerifier("myrealm", secret)
        ok, err = v.verify("GET", "/list-files", {"realm": "myrealm"}, b"", headers)
        assert ok, err

    def test_wrong_secret_fails(self):
        secret1 = generate_realm_secret()
        secret2 = generate_realm_secret()
        headers = sign_request(secret1, "GET", "/x", {}, b"", "r", "n")
        v = RequestVerifier("r", secret2)
        ok, err = v.verify("GET", "/x", {}, b"", headers)
        assert not ok
        assert "invalid signature" in err

    def test_realm_mismatch(self):
        secret = generate_realm_secret()
        headers = sign_request(secret, "GET", "/x", {}, b"", "realm_a", "n")
        v = RequestVerifier("realm_b", secret)
        ok, err = v.verify("GET", "/x", {}, b"", headers)
        assert not ok
        assert "realm mismatch" in err

    def test_post_with_body(self):
        secret = generate_realm_secret()
        body = b'{"event":"commit","vpath":"a/b"}'
        headers = sign_request(secret, "POST", "/notify", {}, body, "r", "n")
        v = RequestVerifier("r", secret)
        ok, err = v.verify("POST", "/notify", {}, body, headers)
        assert ok, err

    def test_tampered_body_fails(self):
        secret = generate_realm_secret()
        body = b'{"event":"commit"}'
        headers = sign_request(secret, "POST", "/notify", {}, body, "r", "n")
        v = RequestVerifier("r", secret)
        ok, err = v.verify("POST", "/notify", {}, b'{"event":"delete"}', headers)
        assert not ok
        assert "invalid signature" in err


@pytest.mark.unit
class TestTimestampSkew:
    def test_fresh_timestamp_passes(self):
        secret = generate_realm_secret()
        headers = sign_request(secret, "GET", "/x", {}, b"", "r", "n")
        v = RequestVerifier("r", secret, skew_secs=60)
        ok, err = v.verify("GET", "/x", {}, b"", headers)
        assert ok, err

    def test_old_timestamp_rejected(self):
        secret = generate_realm_secret()
        headers = sign_request(secret, "GET", "/x", {}, b"", "r", "n")
        # Fake the timestamp to be 200 seconds ago
        headers[HEADER_TIMESTAMP] = str(int(time.time()) - 200)
        # Re-sign with old timestamp won't match, but let's test the skew check
        # by crafting a valid signature with an old timestamp
        from ffspeer_auth import canonical_string
        import hashlib, hmac as _hmac
        ts = str(int(time.time()) - 200)
        nonce = headers[HEADER_NONCE]
        canon = canonical_string("GET", "/x", {}, ts, nonce, b"")
        sig = _hmac.new(secret.encode(), canon.encode(), hashlib.sha256).hexdigest()
        headers[HEADER_TIMESTAMP] = ts
        headers[HEADER_SIGNATURE] = sig
        v = RequestVerifier("r", secret, skew_secs=60)
        ok, err = v.verify("GET", "/x", {}, b"", headers)
        assert not ok
        assert "timestamp skew" in err


@pytest.mark.unit
class TestNonceReplay:
    def test_same_nonce_rejected(self):
        secret = generate_realm_secret()
        headers = sign_request(secret, "GET", "/x", {}, b"", "r", "n")
        v = RequestVerifier("r", secret)
        ok1, _ = v.verify("GET", "/x", {}, b"", headers)
        assert ok1
        ok2, err = v.verify("GET", "/x", {}, b"", headers)
        assert not ok2
        assert "nonce reuse" in err

    def test_different_nonces_ok(self):
        secret = generate_realm_secret()
        v = RequestVerifier("r", secret)
        h1 = sign_request(secret, "GET", "/x", {}, b"", "r", "n")
        h2 = sign_request(secret, "GET", "/x", {}, b"", "r", "n")
        ok1, _ = v.verify("GET", "/x", {}, b"", h1)
        ok2, _ = v.verify("GET", "/x", {}, b"", h2)
        assert ok1
        assert ok2


@pytest.mark.unit
class TestNonceCache:
    def test_eviction_by_age(self):
        nc = NonceCache(max_size=100, expiry_secs=10)
        # Manually insert an old entry
        nc._cache["old_nonce"] = time.time() - 20
        # New nonce should trigger eviction of old one
        result = nc.check_and_store("new_nonce", time.time())
        assert result is True
        assert "old_nonce" not in nc._cache

    def test_eviction_by_size(self):
        nc = NonceCache(max_size=3, expiry_secs=9999)
        for i in range(3):
            nc.check_and_store(f"n{i}", time.time())
        assert len(nc._cache) <= 3
        nc.check_and_store("overflow", time.time())
        assert len(nc._cache) <= 3


@pytest.mark.unit
class TestManualApproval:
    def test_approved_peer_passes(self):
        secret = generate_realm_secret()
        headers = sign_request(secret, "GET", "/x", {}, b"", "r", "node-a")
        v = RequestVerifier("r", secret, manual_approval=True,
                            approved_peers={"node-a"})
        ok, err = v.verify("GET", "/x", {}, b"", headers)
        assert ok, err

    def test_unapproved_peer_rejected(self):
        secret = generate_realm_secret()
        headers = sign_request(secret, "GET", "/x", {}, b"", "r", "node-b")
        v = RequestVerifier("r", secret, manual_approval=True,
                            approved_peers={"node-a"})
        ok, err = v.verify("GET", "/x", {}, b"", headers)
        assert not ok
        assert "peer not approved" in err

    def test_no_manual_mode_allows_all(self):
        secret = generate_realm_secret()
        headers = sign_request(secret, "GET", "/x", {}, b"", "r", "unknown-node")
        v = RequestVerifier("r", secret, manual_approval=False)
        ok, err = v.verify("GET", "/x", {}, b"", headers)
        assert ok, err


@pytest.mark.unit
class TestMissingHeaders:
    def test_missing_signature(self):
        secret = generate_realm_secret()
        headers = sign_request(secret, "GET", "/x", {}, b"", "r", "n")
        del headers[HEADER_SIGNATURE]
        v = RequestVerifier("r", secret)
        ok, err = v.verify("GET", "/x", {}, b"", headers)
        assert not ok
        assert "missing auth headers" in err

    def test_missing_nonce(self):
        secret = generate_realm_secret()
        headers = sign_request(secret, "GET", "/x", {}, b"", "r", "n")
        del headers[HEADER_NONCE]
        v = RequestVerifier("r", secret)
        ok, err = v.verify("GET", "/x", {}, b"", headers)
        assert not ok
        assert "missing auth headers" in err
