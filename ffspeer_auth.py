"""
ffspeer_auth.py — HMAC request signing and verification for FFSFS peer auth.
"""

import hashlib
import hmac
import os
import secrets
import time
import threading
from collections import OrderedDict
from typing import Optional, Tuple
from urllib.parse import urlencode


TIMESTAMP_SKEW_SECS = 60
NONCE_CACHE_MAX = 10000
NONCE_EXPIRY_SECS = 120

HEADER_REALM = "X-FFSFS-Realm"
HEADER_NODE = "X-FFSFS-Node"
HEADER_TIMESTAMP = "X-FFSFS-Timestamp"
HEADER_NONCE = "X-FFSFS-Nonce"
HEADER_SIGNATURE = "X-FFSFS-Signature"


def generate_realm_secret() -> str:
    return secrets.token_hex(32)


def secret_from_passphrase(passphrase: str, realm: str) -> str:
    salt = f"ffsfs-realm-{realm}".encode()
    dk = hashlib.pbkdf2_hmac("sha256", passphrase.encode(), salt, iterations=600_000)
    return dk.hex()


def _body_hash(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def canonical_string(method: str, path: str, query_params: dict,
                     timestamp: str, nonce: str, body: bytes) -> str:
    method_upper = method.upper()
    sorted_params = sorted(query_params.items())
    canonical_query = urlencode(sorted_params) if sorted_params else ""
    bhash = _body_hash(body)
    return f"{method_upper}\n{path}\n{canonical_query}\n{timestamp}\n{nonce}\n{bhash}"


def sign_request(realm_secret: str, method: str, path: str,
                 query_params: dict, body: bytes,
                 realm: str, node_name: str) -> dict:
    timestamp = str(int(time.time()))
    nonce = secrets.token_hex(16)
    canon = canonical_string(method, path, query_params, timestamp, nonce, body)
    sig = hmac.new(realm_secret.encode(), canon.encode(), hashlib.sha256).hexdigest()
    return {
        HEADER_REALM: realm,
        HEADER_NODE: node_name,
        HEADER_TIMESTAMP: timestamp,
        HEADER_NONCE: nonce,
        HEADER_SIGNATURE: sig,
    }


class NonceCache:
    def __init__(self, max_size: int = NONCE_CACHE_MAX,
                 expiry_secs: float = NONCE_EXPIRY_SECS):
        self._max_size = max_size
        self._expiry_secs = expiry_secs
        self._cache: OrderedDict = OrderedDict()
        self._lock = threading.Lock()

    def check_and_store(self, nonce: str, timestamp: float) -> bool:
        now = time.time()
        with self._lock:
            self._evict(now)
            if nonce in self._cache:
                return False
            self._cache[nonce] = now
            return True

    def _evict(self, now: float) -> None:
        cutoff = now - self._expiry_secs
        while self._cache:
            oldest_key, oldest_ts = next(iter(self._cache.items()))
            if oldest_ts < cutoff or len(self._cache) >= self._max_size:
                self._cache.popitem(last=False)
            else:
                break


class RequestVerifier:
    def __init__(self, realm: str, realm_secret: str,
                 skew_secs: float = TIMESTAMP_SKEW_SECS,
                 approved_peers: Optional[set] = None,
                 manual_approval: bool = False):
        self.realm = realm
        self.realm_secret = realm_secret
        self.skew_secs = skew_secs
        self.approved_peers = approved_peers or set()
        self.manual_approval = manual_approval
        self._nonce_cache = NonceCache()

    def verify(self, method: str, path: str, query_params: dict,
               body: bytes, headers: dict) -> Tuple[bool, str]:
        req_realm = headers.get(HEADER_REALM, "")
        req_node = headers.get(HEADER_NODE, "")
        req_ts = headers.get(HEADER_TIMESTAMP, "")
        req_nonce = headers.get(HEADER_NONCE, "")
        req_sig = headers.get(HEADER_SIGNATURE, "")

        if not all([req_realm, req_node, req_ts, req_nonce, req_sig]):
            return False, "missing auth headers"

        if req_realm != self.realm:
            return False, "realm mismatch"

        try:
            ts_val = float(req_ts)
        except ValueError:
            return False, "invalid timestamp"

        now = time.time()
        if abs(now - ts_val) > self.skew_secs:
            return False, "timestamp skew too large"

        if not self._nonce_cache.check_and_store(req_nonce, ts_val):
            return False, "nonce reuse"

        canon = canonical_string(method, path, query_params, req_ts, req_nonce, body)
        expected_sig = hmac.new(
            self.realm_secret.encode(), canon.encode(), hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(req_sig, expected_sig):
            return False, "invalid signature"

        if self.manual_approval and req_node not in self.approved_peers:
            return False, "peer not approved"

        return True, ""
