# ADR-0124: Bounded config-history retention for oversized snapshots

**Status:** Proposed (owner decisions recorded; implementation pending)
**Date:** 2026-08-04

## Context

Config history currently has a visibility gap. An accepted snapshot whose
normalized TOML is at most 10 MiB is recorded as a rollback-capable v2 JSON
envelope. A larger accepted snapshot returns `SkippedOversize`; the persister
logs a warning and leaves the history unchanged. The apply is still valid and
durable, but `ListConfigHistory` has no row proving that it happened. A later
small apply can therefore make the visible chronology appear to jump across an
accepted generation.

That 10 MiB boundary is a history-storage boundary, not a daemon-wide config
limit. Streaming Plan/Apply admits a candidate up to 384 MiB. Commit-confirm
v3 can separately retain a raw normalized prior snapshot up to 384 MiB so a
restart can revert an unconfirmed transaction. The name "v3" in that journal
is not a config-history generation: it has different files, authority,
lifecycle, and recovery obligations. Shipped config history recognizes only
legacy v1 TOML and v2 JSON rows.

The current mixed-history scan also decodes every recognized final file before
sorting it. The writer normally maintains the 20-row cap, but a damaged,
manually copied, or older over-cap directory can make a read allocate for more
than 20 envelopes before anything rejects or repairs it. Adding another row
format must close that pre-decode count gap rather than merely give the new
format a small per-row cap.

### Shipped contract and numeric sources

These are code-derived boundaries at the decision base, not estimates of
typical configuration size:

| Claim | Shipped source | Contract |
|---|---|---|
| Shared history depth is 20 rows | `src/config_history.rs` (`HISTORY_LIMIT`) | Legacy and v2 finals share one sequence namespace and one newest-first limit. |
| Legacy payload cap is 10 MiB | `src/config_history.rs` (`MAX_ENTRY_BYTES`) | A larger legacy final is unreadable. |
| V2 normalized-TOML cap is 10 MiB | `src/config_history/v2.rs` (`MAX_TOML`) and `record_accepted` in `src/config_history.rs` | A newly accepted larger snapshot is skipped before the history writer mutates the directory. |
| V2 manifest cap is 16 MiB | `src/config_history/v2.rs` (`MAX_MANIFEST`, enforced by `validate_manifest`) | The canonical serialized external-source manifest is bounded independently of its item-count and text-field limits. |
| V2 envelope cap is 32 MiB | `src/config_history/v2.rs` (`MAX_ENVELOPE`) | Metadata and normalized TOML together must fit the encoded-envelope bound. |
| Streamed candidate cap is 384 MiB | `crates/api/src/config_service/stream.rs` (`MAX_CANDIDATE_BYTES`) | The transaction ingress may accept a config far larger than history v2. |
| Commit-confirm v3 raw-prior cap is 384 MiB | `src/confirm_journal/v3.rs` (`MAX_RAW_BYTES`) | This is restart-revert authority, not config history. `src/confirm_journal.rs` and `src/confirm_journal/v3.rs` keep the journal generations separate from `src/config_history`. |
| History currently has only v1/v2 formats | `StoredFormat`, `parse_mixed_name`, and `open_and_decode` in `src/config_history/v2.rs` | Recognized finals are legacy `*.toml` or `v2-*.json`; rollback payloads are legacy or v2. |
| Listing decodes before enforcing a count | `scan_pinned` in `src/config_history/v2.rs` | The directory loop calls `open_and_decode` for each recognized final and only sorts afterwards. |
| History recording is best effort | `record_history` in `src/config_persister.rs` | A recording failure warns but does not undo an already accepted durable config. |

The size budgets below use those binary units and intentionally exclude
allocator bookkeeping:

| Case | Payload budget | Derivation |
|---|---:|---|
| Twenty proposed metadata-only v3 finals | 1.25 MiB | `20 × 64 KiB` |
| One proposed v3 stage beside twenty maximum v2 finals | 640.0625 MiB | `20 × 32 MiB + 64 KiB`; this is below the current 672 MiB envelope-shaped transient (`20 × 32 MiB` retained rows plus one 32 MiB decode/encode buffer). |
| Full raw retention at streamed-ingress scale | 7.5 GiB before envelopes/manifests | `20 × 384 MiB = 7,680 MiB`. |
| Full retention through the current clone-and-JSON shape | 8.625 GiB transient before overhead | Twenty 384 MiB decoded payloads plus the accepted input, the envelope's owned clone, and the serialization buffer is exactly `23 × 384 MiB = 8,832 MiB = 8.625 GiB`, before JSON expansion, manifests, or allocator overhead. |

The last estimate is deliberately conservative as a design warning, not an RSS
measurement. JSON escaping or provenance metadata can make it worse. It is
enough to reject "just raise the v2 cap" without first building and measuring a
fundamentally different storage engine.

## Decision

### Owner decisions

The following calls are made here and are not deferred to the implementation:

1. Attempt to preserve an audit row at every existing recording point for an
   accepted oversized normalized snapshot, but do not retain its normalized
   TOML or external-source manifest in config history. Recording remains best
   effort, as it is today.
2. Introduce a prospective config-history v3 metadata envelope for normalized
   snapshots **strictly larger than** 10 MiB. Exactly 10 MiB remains eligible
   for v2. V1 and v2 behavior otherwise stays unchanged.
3. Keep v1, v2, and v3 in the same 20-row sequence and index chronology. There
   is no second metadata ring and no increase to total retained finals.
4. Make v3 rows permanently metadata-only and rollback-ineligible. Hashes are
   evidence of accepted identity, not a promise that the omitted bytes can be
   reconstructed.
5. Bound every encoded v3 final and stage at 64 KiB and bound listing before
   decoding. These are hard correctness limits, not tuning defaults.
6. Do not add raw-payload retention, an object store, a side index, garbage
   collection, backfill, or a v2 cap lift. A future proposal for any of those
   must carry its own durability, confidentiality, resource, and migration
   evidence.
7. Keep commit-confirm v3 independent. Its raw prior is authoritative only
   while a confirmed transaction is pending. Locator-free cleanup residue may
   survive a terminal cleanup failure, but it is never history authority or a
   config-history payload and must not be linked, copied, promoted, or adopted.
8. Do not persist eviction tombstones. Report the number of rows evicted by a
   successful record through the daemon's existing event/metrics plumbing;
   one bounded report describes the record rather than consuming more history
   slots with deletion records.

The value judgment is explicit: truthful bounded chronology for a large
accepted config is worth at most 1.25 MiB across the retained history. General
rollback of 384 MiB configs is not worth multi-GiB retained secret-bearing
payloads, 8.625 GiB of transient allocation before overhead in the current shape,
and a new long-lived storage lifecycle.

### Metadata-only v3 envelope

The canonical v3 JSON envelope contains exactly these semantic fields:

| Field | Meaning |
|---|---|
| `version` | Integer `3`. This versions config history only. |
| `sequence` | Shared monotonic v1/v2/v3 sequence number. |
| `timestamp_unix_seconds` | Recording time, matching the final filename. |
| `normalized_toml_bytes` | Exact byte length of the accepted normalized TOML. |
| `sha256` | SHA-256 of those normalized TOML bytes. |
| `source_sha256` | Existing accepted-source domain digest from `AcceptedConfigSnapshot`, covering the normalized-TOML digest and canonical external-source roster. The roster itself is not retained. |
| `summary` | One-line, redacted identity/object-count summary derived from the already accepted config, never by retaining or reparsing the large TOML. UTF-8 encoding is capped at 4 KiB. |
| `metadata_only_reason` | Stable enum/string value `normalized_toml_exceeds_v2_payload_limit`. It says why no rollback payload exists. |

No catch-all metadata map is allowed. The codec denies unknown fields, checks
the filename/envelope sequence, timestamp, and digest binding, validates
canonical encoding, and rejects an encoded row over 64 KiB before publication.
The summary may include the same non-secret identity and counts as today's
redacted history summary (ASN, router ID, and object counts); it must not carry
descriptions, paths, policy text, addresses other than that established
identity surface, credentials, key material, or raw config excerpts. If the
bounded summary cannot be produced, recording fails before history mutation;
the implementation must not substitute unbounded debug output.

V3 deduplication examines only the newest row, and only when that row is a
verified metadata-only v3 row. It then compares `sha256`, `source_sha256`, and
`normalized_toml_bytes`. An unreadable or v1/v2 newest row never deduplicates a
new v3 record by looking farther back. A byte-identical accepted source
generation does not grow history. A change to either normalized TOML or any
accepted external source creates a new row even when the redacted summary is
unchanged.

The final uses the existing owner-private history directory and atomic
stage/fsync/rename/directory-fsync publication pattern. File mode remains
`0600`, directory mode remains `0700`, symlinks and non-owner files fail
closed, and a crash stage is not a history row. The implementation may add a
`v3-...json` filename, but it must preserve the shared numeric sequence and
must not infer identity only from that filename.

### One chronology and a bounded two-pass listing

Listing uses one pinned directory descriptor and exactly two logical passes:

1. Enumerate names, recognize v1/v2/v3 **finals** without opening or decoding
   their contents, and collect at most 20 exact names. If a 21st recognized
   final is observed, reject the whole listing as unsafe before any final is
   decoded. Duplicate sequences and unreadable files still count; stages and
   unrelated names do not.
2. Decode only the collected roster, therefore at most 20 rows. Preserve the
   existing exact-object identity checks, newest-first sort, duplicate-sequence
   unreadable treatment, per-format caps, digest verification, and redacted
   output.

The second pass never re-enumerates into a larger roster. A concurrent writer
may make one collected name disappear or publish a newer final after the
roster was captured; the former becomes unreadable/fails under the existing
identity rules and the latter appears on the next listing. Neither case can
cause more than 20 decodes.

The writer also performs name-only bound enforcement before decoding existing
rows. It may repair an old over-cap directory by validating and evicting the
oldest recognized finals under the existing crash-consistent writer lock, but
the read API never allocates through an over-cap directory in order to repair
it.

### API and rollback contract

`ListConfigHistory` gains an additive `METADATA_ONLY` provenance status plus
the normalized byte count and metadata-only reason. It returns the two hashes,
timestamp, and redacted summary for a verified v3 row. Human and JSON output
must call it metadata-only and rollback-ineligible; it must never group it with
`RECORDED` v2 rows merely because both hashes are present.

`RollbackConfigTransaction` refuses a selected v3 row before opening external
sources, creating commit-confirm authority, planning, or mutating state. The
stable gRPC category is `FAILED_PRECONDITION`, with a non-secret message that
the selected config-history row is metadata-only because its normalized TOML
exceeded the history payload limit. This applies whether or not the caller
supplies a confirm ID. The existing index-zero `INVALID_ARGUMENT` rule still
takes precedence because index zero is never a legal rollback target.

V3 hashes cannot authorize a restore from the current config file, a caller
upload, commit-confirm residue, or live external files. Hash equality proves
identity only after bytes are independently available; config history has
deliberately not retained those bytes.

### Failure matrix

| Condition | Record/list result | Rollback result | History mutation |
|---|---|---|---|
| Accepted normalized TOML `<= 10 MiB` | Existing v2 record/dedup and existing listing status | Existing eligible-v2 provenance checks | Existing v2 behavior |
| Accepted normalized TOML `> 10 MiB` and within accepted ingress bounds | V3 metadata row, or dedup against identical newest v3 identity | `FAILED_PRECONDITION` for a selected v3 row | One atomic v3 final, shared eviction to 20 |
| Candidate exceeds the 384 MiB streamed-ingress cap | Rejected before it is an accepted snapshot | N/A | None |
| V3 canonical encoding would exceed 64 KiB, or summary exceeds its bound | Best-effort history warning; prior rows remain listable | No new row exists | None; size validation precedes eviction/stage creation |
| V3 stage creation, write, or pre-publish sync fails | Accepted config remains authoritative; warning names history recording failure without config content | Existing older rows retain their behavior | None; cleanup follows existing stage rules |
| Error or crash after one or more oldest-row evictions but before v3 publish | Listing returns only the surviving complete finals; the new generation is absent and a returned error warns when the process survives | Surviving rows retain their existing behavior | Some oldest complete rows may already be gone; no torn final is created, and a later writer resumes from the surviving roster |
| V3 rename publishes a complete final but final directory sync fails | Accepted config remains authoritative; recording warns; the complete final may be visible and is revalidated normally | The row's verified status controls rollback refusal | Never a torn final; the next writer/list sees either the old roster or the complete new final |
| Crash leaves a v3 stage | Stage is ignored by listing and safely removed by the writer | N/A | No final chronology row until publish completed |
| At most 20 finals, but a v3 row is corrupt, non-canonical, unsafe, or digest-mismatched | Row is `UNREADABLE`; no unverified hashes/summary are exposed | `FAILED_PRECONDITION` under existing unreadable-row rule | None |
| A final name is swapped during the decode pass | The decoder uses one descriptor-relative, no-follow open and records that object's identity; an unsafe or mismatched target is `UNREADABLE`, and a post-open rename cannot change the bytes being verified | A selected v3 row refuses from its verified listed status without payload access; a selected payload-bearing v1/v2 row must reopen the recorded identity | None |
| A final is replaced after listing but before a payload-bearing rollback reopens it | The listed metadata remains tied to the originally decoded object; the v1/v2 reopen identity check rejects the replacement | V1/v2 returns `FAILED_PRECONDITION` (`entry became unavailable or unsafe`) before payload use; v3 always refuses earlier without reopening | None |
| Duplicate sequence among at most 20 mixed finals | Every colliding row is `UNREADABLE`, as today | `FAILED_PRECONDITION` | None |
| More than 20 recognized mixed finals | Listing rejects before decoding any final; rollback's list step fails closed | `FAILED_PRECONDITION` | Read path does not repair; writer may repair name-first |
| External source changes after a v3 row was recorded | Stored source hash remains historical evidence only | Always `FAILED_PRECONDITION`; no source reopen | None |
| Upgrade finds existing v1/v2 rows | Mixed list and rollback semantics remain unchanged | Existing v1/v2 rules | No backfill or rewrite |
| Writable downgrade encounters a v3 final | Unsupported after v3 publication: the older binary ignores v3 and may expose stale rows or reuse its sequence; stop the daemon and preserve the directory for the new binary or move the complete history directory aside before starting the old binary | No v3 restore path; re-upgrade refuses duplicate sequences or an over-cap roster rather than blessing the collision | An old writer can add colliding v1/v2 rows if the operator violates the move-aside rule; there is no down-conversion |

For `ListConfigHistory`, an over-cap roster remains the existing
storage-unavailable/unsafe server error category rather than a partial list.
For rollback, the same condition is deliberately the stable
`FAILED_PRECONDITION` category because a safe target cannot be resolved.

### Phased implementation outline

1. **Codec and store.** Add a history-v3 codec with canonical/size validation,
   accepted-snapshot summary construction, shared sequence allocation,
   newest-row dedup within the mixed-generation chronology, name-first
   eviction, and the existing atomic
   owner-private publication boundary. Return the successful eviction count to
   the existing event/metrics observability path. Select v2 versus v3 only
   after checking the normalized byte length and before any eviction.
2. **Bounded mixed scan.** Split filename collection from payload decoding,
   add v3 recognition, and freeze the reject-before-decode 21st-final rule.
   Keep pinned-object, mode/owner, digest, duplicate-sequence, and concurrent
   replacement checks.
3. **Read API and CLI.** Append the protobuf metadata-only status and additive
   fields, render them in human/JSON listings, and add the explicit
   `FAILED_PRECONDITION` rollback branch before payload access.
4. **Executable proof.** Add boundary tests at 10 MiB and 10 MiB + 1 byte,
   canonical 64 KiB limits, 20-row mixed eviction, 20-v3 1.25 MiB budgeting,
   mixed-generation ordering and newest-row dedup, crash points, corrupt v3
   rows, duplicate
   sequences, and a 21-final fixture proving zero payload opens/decodes. A
   mutation-proven rollback test must show that a selected v3 row reaches no
   external-source read, journal create, planner, persister, or runtime actor.
5. **Operational truth-up.** Only after code and proofs ship, update API,
   operations, deployment, security, and release documentation to describe
   metadata-only rows. Do not claim large-config rollback.

No phase performs a v1/v2 rewrite or backfill. A large accepted generation that
predates activation remains absent; fabricating its metadata from the current
file would falsely attribute time and sequence identity.

## Alternatives considered

### Keep skipping oversized history

This has the smallest implementation cost and no new API surface, but silently
loses accepted generations from the operator's bounded chronology. The warning
is ephemeral and cannot answer which normalized/source identity was accepted.
Rejected because the gap is avoidable with tightly bounded metadata.

### Lift v2 to 384 MiB and retain full payloads

This preserves rollback, but the 20-row raw normalized-TOML budget alone is
7.5 GiB and the current clone/serialization shape reaches 8.625 GiB transient
before overhead. It also turns external-source manifests and secret-bearing
normalized config into a much larger durable corpus. Rejected.

### Store raw payloads in a content-addressed object store

Deduplication could reduce some fleets' disk use and enable restore, but it
introduces reference accounting, index recovery, garbage collection, orphan
policy, quotas, crash ordering, downgrade behavior, and another sensitive-data
lifecycle. There is no measured demand justifying that subsystem. Rejected;
this ADR does not seed an index or object namespace for it.

### Keep a separate 20-row metadata ring

This avoids evicting a rollback-capable small row when large configs alternate
with small ones. It also permits 40 visible generations, creates two index
spaces, and makes `rollback N` diverge from the chronology shown to the
operator. Rejected in favor of one honest recency budget.

### Store only timestamp, size, and summary

That is cheaper still, but cannot distinguish two large accepted generations
with identical counts or establish normalized/source identity. The two hashes
are bounded, already computed from the accepted snapshot, and materially
improve audit value. Rejected.

### Reuse commit-confirm v3 raw files

Commit-confirm storage is temporary revert authority with terminal cleanup;
history is best-effort retained chronology. Coupling them would either let
history influence boot authority or let confirmation delete history payload.
Rejected as a category error despite the shared generation number.

## Consequences

- After implementation, a successful oversized apply can no longer disappear
  from the last-20 accepted-config chronology solely because of its size.
- Mixed history stays bounded by count before decode and by bytes per format.
  Twenty v3 finals consume at most 1.25 MiB encoded.
- A large row is observable but not restorable. Operators must keep their own
  source-controlled config and external policy data; the hashes help identify
  the accepted generation but cannot recover it.
- Large applies can evict older rollback-capable rows because all generations
  share one honest recency window. This is intentional.
- Hashes reveal equality across generations, as existing history hashes do,
  but v3 adds no raw secret-bearing config or external-source paths.
- V1/v2 compatibility and rollback remain intact. The new protobuf fields are
  additive. Existing `rbgp` clients render an unrecognized status value as
  `unknown`; no client may infer rollback eligibility from non-empty hashes.
- A malformed over-cap directory fails closed without first paying its payload
  allocation cost. Operators repair it through the writer/administrative
  storage path, not a partial list.

## Current validation gate

Executable red proof is N/A for this docs-only Proposed ADR. The current gate
is source-path verification of every shipped and numeric claim above, ADR index
and Markdown-link integrity, `cargo fmt --check`, warning-denied `cargo doc`,
and a diff proving that only this ADR and the ADR index changed. The phased
implementation must supply the mutation-proven red proofs before status can
change to implemented.

## References

- [ADR-0076](0076-config-transaction-model.md), config transactions and
  commit-confirm
- [ADR-0121](0121-config-history-external-policy-provenance.md), v2 history
  source identity and restore
- `src/config_history.rs` and `src/config_history/v2.rs`, shipped mixed history
- `src/config_persister.rs`, best-effort recording boundary
- `src/confirm_journal.rs` and `src/confirm_journal/v3.rs`, separate
  commit-confirm recovery generations
- `crates/api/src/config_service/stream.rs`, streamed candidate admission cap
