# FFSFS Authentication and Transport Design

This captures the current design decision for peer authentication, manual
approval, HTTP, and HTTPS. It is intentionally MVP-oriented.

## Conclusions

- Every realm should have a `realm_secret`.
- The realm secret is always required for peer data exchange.
- Manual peer approval is optional per node.
- Discovery can remain automatic, but discovered nodes are candidates until
  they authenticate with the realm secret.
- Peer notifications are hints only. They do not force sync and do not push
  file bytes into another peer.
- Default sync remains pull-based.
- HTTP remains supported for trusted LAN performance.
- HTTPS should be supported as optional transport privacy, not as the primary
  authentication mechanism.
- Direct public-IP exposure is not supported yet. Public Internet use needs
  additional transport, identity, DoS, peer-scaling, and operational hardening;
  see `public_internet_exposure.md`.

## Authentication

The MVP authentication primitive is request signing with the realm secret.

Each peer request should include headers like:

```text
X-FFSFS-Realm
X-FFSFS-Node
X-FFSFS-Timestamp
X-FFSFS-Nonce
X-FFSFS-Signature
```

`X-FFSFS-Signature` should be an HMAC over stable request fields:

```text
method + path + canonical_query + timestamp + nonce + body_hash
```

Verification should reject:

- realm mismatch
- timestamp outside the skew window
- recently seen nonce
- invalid signature
- unapproved peer when manual approval is enabled

This protects HTTP from random LAN peers joining or forging requests. It does
not hide filenames, metadata, or file bytes from a passive network observer.
That is acceptable for trusted LAN mode when documented clearly.

## Approval Modes

Two primary modes are enough for MVP:

- `peer_trust=realm_secret`: any peer with the realm secret may participate.
- `peer_trust=manual`: a peer must know the realm secret and also be approved
  locally before data exchange.

Manual approval can be asymmetric. Each node may decide whether it trusts a
peer. Paranoid mode is both nodes requiring approval.

Unknown or unapproved peers should be visible as pending/candidate peers, but
should not be allowed to list, fetch, or otherwise exchange realm data.

## Transport

`peer_transport=http` should remain supported because it has less overhead and
is useful on trusted gigabit LANs.

`peer_transport=https` should be a minimal transport option:

- Flask can start with `ssl_context=(cert_path, key_path)` when configured.
- Self-signed certificates are acceptable during early development.
- Certificate validation and mTLS are not the MVP trust model.
- HMAC realm authentication should still be required over HTTPS.

HTTPS provides confidentiality against passive observers. HMAC proves realm
membership.

## SSH

SSH trust should not automatically imply FFSFS trust.

Useful future SSH helpers:

- fetch a remote FFSFS node fingerprint over SSH
- approve a peer by SSH bootstrap
- optionally push this node's fingerprint to the remote host

Runtime peer authentication should still use FFSFS realm auth and, later, node
keys/fingerprints.

## Future Extensions

After MVP:

- per-node keypairs and fingerprints
- peer revocation
- per-peer capabilities such as list/fetch/notify/replica-source
- SSH bootstrap command
- certificate validation or mTLS for remote exposure
