# Public Internet Exposure

FFSFS does not currently support exposing the peer HTTP service directly on the
public Internet.

The current peer stack is for trusted LANs, isolated VM networks, and private
overlay networks where endpoints are deliberately configured. A public IP
deployment has a different threat and operations model and needs explicit
hardening before it is safe to document as supported.

## Current Boundary

Supported today:

- Localhost and trusted LAN operation.
- Private overlay networks such as Tailscale, treated as ordinary reachable
  interfaces, not as a separate trust mode.
- Explicit known-peer configuration.
- HMAC request signing with a per-realm secret.
- Optional manual peer approval by node name.
- Optional bandwidth/rate limits for normal foreground/background traffic.

Unsupported today:

- Directly binding the peer HTTP API to a public IP.
- Port-forwarding the peer HTTP API from a home router to the Internet.
- Relying on current Flask development serving behavior as an Internet-facing
  service boundary.
- Large open peer sets or public discovery.
- Anonymous Internet clients, public signup, or multi-tenant operation.

## Major Blockers

### Transport Security

HTTP with HMAC proves realm membership but does not hide filenames, paths,
metadata, response sizes, or file bytes from passive observers. Public Internet
use needs HTTPS as a real supported mode, including certificate configuration,
renewal guidance, and clear validation behavior.

HMAC must remain required over HTTPS. TLS confidentiality and realm membership
are separate concerns.

### Secret and Identity Model

The current realm secret is shared by all peers. If one node is compromised,
the attacker can impersonate realm membership until the secret is rotated
everywhere. Public exposure needs per-node identity keys, fingerprints,
revocation, and key rotation.

Manual approval currently approves node names from signed requests. Public
deployment needs stronger node identity binding than a self-declared name.

### Denial of Service

Internet-facing peers need protection before request handlers do meaningful
work. Current rate limits are intended for configured traffic, not hostile
traffic. Missing or incomplete pieces include:

- per-source connection and request limits
- request body size limits
- cheap rejection before JSON parsing or disk scans
- slow-client protection for streaming file responses
- global concurrency caps for expensive routes
- bounded peer-cache growth
- clear behavior under repeated failed auth attempts

### Resource Amplification

Routes such as listing, head lookup, sync status, peer cache refresh, and file
serving can trigger disk work, memory growth, or long-lived streams. Public
exposure needs explicit cost bounds and backpressure so unauthenticated or
barely authenticated clients cannot force excessive CPU, memory, disk, or
network use.

### Many-Peers Problem

The current design assumes a small, human-managed peer set. Public or wide-area
deployments need limits and policies for:

- maximum known peers
- pending/candidate peers
- peer eviction and stale-peer pruning
- gossip fanout and seed aging
- per-peer capabilities
- scheduling across slow/intermittent links
- conflict and retry behavior when many peers disagree or flap

### Discovery and Addressing

UDP discovery is LAN-oriented. Public deployment should not depend on broadcast
or unsolicited Internet discovery. It needs explicit seed hosts, stable
endpoints, NAT/firewall guidance, and a way to deduplicate the same node seen
through LAN, overlay, and public addresses.

### Web/Admin Surface

The planned web configuration UI must not be exposed publicly without its own
session authentication, CSRF protection, lockout/rate limiting, and careful
separation from the realm secret. The host admin password being collected by
setup is future plumbing, not a complete public admin security model.

### Operational Hardening

Direct public service needs operational guidance that does not exist yet:

- reverse proxy or production WSGI server stance
- firewall examples
- log/audit expectations
- metrics for auth failures and traffic
- safe defaults for bind address
- backup and recovery guidance for compromised secrets
- update and vulnerability response process

## Likely Path to Support

Public-IP support should be a separate hardening milestone, not an accidental
configuration option. A plausible sequence:

1. Keep default setup on LAN/overlay only, with `trust_unknown_peers=false`.
2. Add a public-exposure preflight check that refuses unsafe config.
3. Implement HTTPS as a supported transport mode.
4. Add per-node keys/fingerprints and revocation.
5. Add request/concurrency/body-size limits before expensive route handling.
6. Add pending-peer state and bounded peer tables.
7. Add explicit public seed endpoint configuration and address deduplication.
8. Add VM/integration tests for hostile auth failures and slow/large requests.
9. Document reverse proxy/firewall deployments only after the above is covered.

Until then, use a private overlay network or VPN for remote sites.
