# Format Freeze v1 — on-disk, wire, protocol

> Status: **PROPOSAL.** Nothing here is frozen until the pre-freeze list in §4
> is done and §7's decisions are made. Based on a full inventory of every
> persisted and wire format (2026-09-22), with the ambiguities that inventory
> found listed as blockers rather than footnotes.

## 1. What a freeze is for

A deployed node writes bytes that outlive the version of FFSFS that wrote
them, and talks to nodes that will not be upgraded on the same day. The
freeze is the promise that makes that safe:

> **A v1 reader must be able to read anything a v1-or-later writer produces,
> and must never destroy what it does not understand.**

That is a stronger promise than "the format stops changing", and a weaker one
than "the format is final". It permits new fields, new modes, new endpoints
and new policies; it forbids changing the meaning of what already exists, and
it forbids a reader treating the unfamiliar as the absent.

The second half matters most in this codebase, because FFSFS deletes things —
retention, eviction, reduction. Any of those meeting a construct from a newer
node must refuse to act rather than guess. **Unknown means preserve.**

## 2. What gets frozen

| layer | artifact |
|---|---|
| on-disk | versioned filename grammar; `mode` and `flags` semantics; tombstone/marker meaning; temp-name grammar; volume identity file; realm marker |
| local state | realm config (already versioned), storage-pool block, pending-replication log, node-status document |
| wire | HTTP endpoint set, their parameters and response shapes; the HMAC scheme; the UDP discovery packet |
| naming | realm → port derivation; reserved names (`.ffsfs*`, `.CONFLICT.`, `NULL_HASH`) |

Explicitly **not** frozen, and marked as such so nobody builds on them:
the dashboard HTML and its form actions; `/get-file-deprecated`; the
metadata log (see §5); log formats; anything under `agents/`.

## 3. The compatibility laws

These are the rules a conformance suite tests, and the reason a v2 writer
cannot hurt a v1 reader.

**L1 — Unknown fields survive.** A reader that rewrites a structure it did not
fully understand must carry unknown keys through unchanged. Already true for
the realm config; must become true for the volume id file, the pool config and
the node-status document.

**L2 — Unknown `mode` is opaque, not ordinary.** Today an unrecognised mode
renders as a normal visible file. A v2 that adds, say, `encrypted` would have
v1 nodes serving ciphertext as content. An unknown mode must be treated as
*present but not interpretable*: not served as file content, not counted as a
live version, never pruned, and visible to the operator as an unknown-version
warning.

**L3 — Unknown never gets deleted.** Retention, eviction and reduction skip
anything they cannot parse or whose mode they do not know. A newer node's
tombstone variant must not be prunable by an older node that thinks it is junk.

**L4 — Reserved space is reserved.** `flags` bits above `0o7777` are reserved:
preserved on rewrite, never interpreted, never cleared. Same for unknown
fields in the packet payloads.

**L5 — Capabilities, not versions.** A node advertises what it can do; it does
not ask what version its peer is. Version numbers gate refusal; capability
sets allow partial interoperation. The one legitimate use of a version number
is refusing something from the future you provably cannot handle — which is
exactly what `CONFIG_VERSION` fails to do today (a config claiming version 99
is accepted and left as-is; verified).

**L6 — One writer, one reader, one grammar.** Every format has exactly one
builder and one parser, in one module. Three of today's bugs exist because a
second, unvalidated f-string builder was written elsewhere.

## 4. Pre-freeze blockers

These change bytes or behaviour, so they must land **before** the freeze, not
after. Ordered by consequence.

### 4.1 Two realm→port derivations (BLOCKER)

`ffsutils.default_port_for_realm` uses SHA-256; `ffsfs._port_for_realm` uses
SHA-1. They disagree:

    FFSFS_REALM_V1   bind 23224   dial 43951
    testff           bind 11181   dial 34813

A node binds one and peers dial the other, so "the deterministic port for a
realm" — the thing autodiscovery and bare-hostname peers rely on — is not one
number. Pick SHA-256 (it is the one the setup app, `_advertise_port` and
`_peer_url` already use), delete the other, and treat the change as a flag
day for any existing deployment.

### 4.2 `get_suffix_from_path` emits an unparseable suffix

`file.txt.NULL_HASH.ABC` yields `NULL_HASH.NULL_HASH.ABC` — the doubling
depends on how many dots the logical name has. That suffix goes on the wire in
`notify_modify`, and the receiver stores `f"{vpath}.{suffix}"`, producing a
name that then fails to parse. `tests/test_ffsutils.py:110` asserts the broken
form, so the bug is currently the contract and the test must change with it.

### 4.3 The version timestamp is one second wide

Ordering is `(timestamp, mtime_ns, path)`. The second and third components are
local: `mtime_ns` is not comparable across nodes, and `path` is a tie-break of
last resort. So for two versions committed in the same second on two nodes,
the realm has no defined winner.

Today's commit floor (`max(now, newest+1)`) hides this locally by pushing
stamps forward, at the cost of stamps drifting ahead of the wall clock — one
poisoned future-stamped file drags a file's whole history with it, permanently.

**Recommendation: widen to milliseconds before freezing.** The parser already
accepts an unbounded `\d+`, so a 13-digit stamp parses today; only the builder
and the human-facing formatting change. Doing it after the freeze means either
a format break or living with second-granularity ordering forever.

### 4.4 Peer-supplied names must not build paths (SECURITY)

`ffspeers.py:1294` joins a peer-supplied versioned name to the data root
without the traversal check every other write path uses, and the name grammar
matches `..` across `/`. Freezing the grammar while this exists blesses a
remote write-anywhere. Fix both: route every peer-supplied name through
`_safe_file_abspath`, and forbid `/` and `..` segments in `logical_name` at
the parser, which is a grammar decision and therefore a freeze decision.

### 4.5 Fetch verifies before it replaces (SECURITY)

`ffspeers.py:1297` and `:2486` stream a download onto the final versioned path
with `"wb"` and check the hash afterwards. A peer serving one wrong byte
destroys a good local version, and a concurrent reader can see the half-written
file under its final, hash-bearing name. Download to a temp beside it, verify,
then `os.replace`. This is protocol-visible: it is what makes "a versioned
filename always describes its bytes" true, which is the invariant everything
else rests on.

### 4.6 The HMAC canonical string is too narrow

It covers method, path, sorted query, timestamp, nonce and body hash. It does
**not** cover `X-FFSFS-Realm` or `X-FFSFS-Node`, though both are used for
authorization decisions — so node-name approval is decorative, and a signature
is replayable against any same-realm node (host is unsigned too). Add realm,
node and host to the canonical string. Post-freeze this is a flag day; pre-
freeze it is a one-line change. Also: store the nonce *after* verifying the
signature, not before.

### 4.7 UDP `PROT_VER` is a strict equality check

A packet with any version but `1` is dropped silently. That is the opposite of
forward compatible: a v2 node's beacons become invisible to v1 rather than
partially understood. Define the rule now — *same major, ignore unknown
fields, ignore unknown type bytes* — and make v1 implement it, or v1 nodes will
have to be retired to roll out v2.

Also fix `_handle_query`: a QUERY with a non-numeric `max` raises out of
`int()` and permanently kills that socket's receiver thread.

### 4.8 Close the grammar

Decide and enforce, since a parser that accepts more than any writer produces
is a compatibility trap:

- **hash**: Crockford base32, exactly 26 chars, alphabet without `I L O U`.
  Keep 64-hex as legacy read-only, or drop it — it has not been produced since
  the Crockford switch.
- **`NULL_HASH`**: legal in a temp name, illegal in a committed version. Today
  `ffspeers.py:2827` synthesizes committed tombstones with it while
  `_content_hash_matches` treats it as "nothing to verify" — pick one.
- **`mode`**: a closed set for v1 — `write`, `delete`, `moved`, `symlink`,
  `append` — plus L2's rule for everything else. Drop `copy`, which is in three
  accept-lists and never produced.
- **`logical_name`**: no `/`, no `..`, no control characters, and a length
  bound that makes the committed name fit `NAME_MAX` (see §6).

### 4.9 One builder per format

Delete the raw f-string filename builders at `ffspeers.py:1202` and `:2855`;
both re-emit whatever the parser accepted, with no validation. Same for the
two `.ffsfs` marker writers with incompatible formats at the same path (JSON
vs plain text, both firing on a normal mount, plain text winning).

## 5. The metadata log

`.ffsfs-meta.log` is TAB-separated, unescaped, unbounded, never rotated, on the
primary volume only — and **has no reader anywhere in the repo**, while the
README and `tech_doc.md` describe it as authoritative metadata. A filename
containing a tab or newline produces a silently corrupt record in a format with
no parser to notice.

Two honest options; pick one before freezing:

1. **Declare it a debug artifact.** Document it as append-only diagnostics,
   fix the docs, leave the format alone, add a size cap.
2. **Make it a real journal.** Then it needs escaping, a field count, a
   version line, rotation, fsync, and a parser — and it should be per-volume,
   since a primary-only journal describes a pool it cannot see all of.

Recommendation: (1). The store is self-describing by design — the filenames
*are* the metadata — so a second source of truth earns its keep only if
something reads it.

## 6. Name length

`statfs` advertises `f_namemax: 255` while a committed name costs about 46
characters more than the name the user chose (hash 26 + mode + flags + stamp +
four dots). So a 250-character filename accepts writes and fails at commit with
ENAMETOOLONG, data stranded in an orphan temp, file listed but unopenable.
Report `255 - overhead` and make the overhead a named constant the grammar
owns. A millisecond stamp (§4.3) adds three more characters, which is another
reason to decide it before freezing rather than after.

## 7. Decisions needed

1. **Timestamp granularity** — seconds (freeze as-is, live with undefined
   cross-node same-second ordering) or milliseconds (recommended, one-line
   builder change now, format break later).
2. **Metadata log** — debug artifact or real journal (§5).
3. **Legacy 64-hex hashes** — read-only or dropped.
4. **`mode` set** — confirm the five, and confirm L2's unknown-mode rule,
   which changes today's behaviour of showing unknown modes as ordinary files.
5. **Port derivation flag day** — SHA-256 everywhere means existing test
   deployments move ports once; confirm that is acceptable now rather than
   never.
6. **Multi-drive redundancy** (`agents/audit_2026-09-21.md` P2) — whether a
   single host's volumes count toward `rf:N` is a *protocol-visible* answer,
   because holdings and confirmations are exchanged with peers. Freezing the
   holdings document before deciding this is how a format gets a vestigial
   field.

## 8. Conformance suite

The freeze is only real if it is executable. `tests/test_forward_compat.py`
today covers the realm config and nothing else — not filenames, not the wire,
not HMAC. Proposed additions, all cheap:

- **Golden corpus.** A checked-in directory of version filenames — every mode,
  boundary hashes, unicode and dotted logical names, a future timestamp, an
  unknown mode, an unknown `flags` bit — with the expected parse of each.
  `parse(build(x)) == x` over the corpus, and the corpus is append-only.
- **Unknown-input battery.** For each law in §3, a test that a v1 reader
  tolerates the v2-shaped input and, critically, does not delete it: run
  retention, eviction and reduction over a store containing unknown modes and
  unknown fields and assert nothing is removed.
- **Wire snapshots.** A recorded request/response per endpoint, asserted
  field-by-field, so a response-shape change is a deliberate act.
- **Canonical-string vectors.** Fixed (method, path, query, body, ts, nonce,
  secret) → expected signature, so the HMAC cannot drift silently.
- **Packet vectors.** Byte-exact ANN/QRY/RESP packets, plus a v2-shaped packet
  a v1 node must still partially understand once §4.7 lands.

## 9. Order of work

1. §4.4, §4.5, §4.6 — the security-visible ones; they change what a peer can
   do to you, and they are cheapest before anyone deploys.
2. §4.1, §4.2, §4.9 — one builder, one derivation, one grammar.
3. §7.1 and §7.2 decisions, then §4.3 and §6 together.
4. §4.7, §4.8 — close the grammar and the packet rules.
5. §8 conformance suite, which is what actually ends the freeze process.
6. Tag v1. After the tag, changes are additive only and must pass the suite
   from step 5 unchanged.
