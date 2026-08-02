# ADR-0121: Config-history external-policy provenance

**Status:** Accepted, partially implemented
**Implementation:** v2 recording and mixed listing shipped; v2 restore pending
**Date:** 2026-08-01

## Context

Before v2 activation, applied-config history retained one normalized TOML
document per entry. Its `sha256` covered those bytes, and `rollback N` reparsed
the document through the ordinary transaction path. That was sufficient only
while TOML was the complete input.

An accepted config may also depend on `[policy].rpol_files`, their transitive
imports, and `[policy.datasets]`. Legacy rows retain none of that source
identity, so a later rollback would read whatever those paths contain at that
time rather than necessarily the sources accepted with the recorded TOML. V2
rows now retain the accepted manifest and source digest, but restore remains
refused until the loader can revalidate that identity. The native transaction
fence added in #1370 correctly rejects full-snapshot transactions when either
side has these external inputs; history must not route around that fence by
presenting a TOML-only snapshot as complete.

There is a second distinction to preserve. Config history records the
validated **desired/source snapshot** accepted at boot, persistence, or reload.
It is not an authoritative serialization of effective runtime state: a reload
may pin restart-required fields, and a failed dataset refresh deliberately
keeps the prior accepted dataset serving policy. Provenance must describe the
exact bytes the loader accepted, without claiming that every desired setting
is already effective.

## Decision

### 1. Capture an immutable accepted-source snapshot

The provenance-aware loader returns one immutable object containing the
validated config, its normalized TOML, and its source manifest. Every history
and commit-confirm caller receives that object; provenance is not assembled by
a later observer.

The normalized TOML is exactly the byte string returned by the existing
`persisted_config_document` renderer. It is rendered once into the immutable
object; history, commit-confirm, and any successful persistence handoff reuse
those bytes instead of rendering the config again. The existing `sha256` is
computed over that exact byte string.

For every external file, canonicalize the path, open and read it once, parse
the bytes from that read, and retain metadata derived from those same bytes.
The object must never be reconstructed from the compiled-policy `HashMap`, a
mutable dataset handle, a later filesystem read, or display-form paths. A
failed dataset refresh retains the prior accepted dataset provenance alongside
the prior snapshot; rejected bytes, the failed path resolution, and the error
are not promoted into accepted provenance.

This makes byte identity intentional. A dataset rewrite that parses to the
same set still creates a new history generation because its accepted source
bytes changed. Dataset generation counters do not participate.

### 2. Canonical source manifest

The v2 manifest has this roster and no implicit inputs:

1. The existing SHA-256 of the normalized TOML bytes retained in the
   envelope. Original formatting and comments are not source identity because
   those bytes are not archived and therefore cannot be reproduced later.
2. One rpol unit per `[policy].rpol_files` entry, in configured order.
   Within each unit, modules appear in resolver/file-index order (main file is
   index zero). Each module records its lossless canonical accepted path, raw
   byte length, raw SHA-256, and imported module indices in declaration order.
3. Datasets sorted by dataset-name bytes. Each records name, declared kind,
   lossless canonical accepted path, raw byte length, and raw SHA-256.

Paths use a tagged, lossless platform representation in the envelope (raw
`OsStr` bytes on the supported Unix targets), not `display()` or lossy UTF-8.
Display strings may be derived for local diagnostics but are never identity.

The manifest deliberately excludes mtimes, inode numbers, modes, dataset
generations, mutable handles, refresh errors, convergence state, and rejected
bytes. These are either unstable metadata or operational outcomes, not inputs
whose accepted bytes defined the config.

### 3. Preserve `sha256`; add a source-domain digest

The existing `sha256` remains SHA-256 of normalized TOML exactly. It keeps its
API meaning and is not silently redefined.

The new `source_sha256` is SHA-256 over the canonical roster above, prefixed by
the domain string `rustbgpd.config-source.v2\0`. It is not the hash of a JSON
serialization. Every count and field is encoded as a length-prefixed byte
string (`u64` big-endian length followed by bytes); integers first use their
fixed-width big-endian representation. Unit, module, import, and dataset counts
are included. The existing normalized-TOML digest is the first roster field.
This prevents concatenation ambiguity and makes serializer formatting
irrelevant.

The canonical integer widths are fixed: every field-length and roster count,
and every recorded raw-byte length, is an unsigned 64-bit big-endian value;
each imported module index is an unsigned 32-bit big-endian value. There are no
native-width or signed integers in the digest input. Dataset kinds remain their
length-prefixed ASCII strings rather than an implementation enum ordinal.

Hash verification proves that current files match the recorded accepted
identity. It is not archival: v2 stores no rpol or dataset contents and cannot
restore deleted or changed external files.

### 4. One bounded v2 envelope, never sidecars

A v2 entry is one atomically published, versioned envelope containing:

- format version, sequence, and timestamp;
- normalized TOML, its existing `sha256`, and `source_sha256`;
- the complete inline source manifest.

There are no manifest, digest, or per-source sidecars. A crash can expose the
old entry set or one complete new envelope, never TOML paired with another
generation's provenance.

The envelope encoding is the `serde_json` compact UTF-8 encoding of fixed
`deny_unknown_fields` structs, with no insignificant whitespace and exactly one
trailing LF. Object fields have this exact order:

- envelope: `version`, `sequence`, `timestamp_unix_seconds`, `sha256`,
  `source_sha256`, `normalized_toml`, `manifest`;
- manifest: `toml_sha256`, `rpol_units`, `datasets`;
- rpol unit: `modules`;
- module: `path`, `length`, `sha256`, `imports`;
- dataset: `name`, `kind`, `path`, `length`, `sha256`.

A path is exactly `{"encoding":"unix-bytes-hex","value":"..."}`, where the
value is even-length lowercase hex of raw `OsStr` bytes. Dataset kinds are the
exact strings `prefix-set`, `asn-set`, and `community-set`; digests are
lowercase hex and import indices are unsigned JSON integers. The decoder
rejects duplicate/unknown fields and noncanonical enum, integer, hex, or path
forms, then requires byte-for-byte equality with a compact re-encoding plus LF.

The serialized manifest is the manifest value encoded by that same compact
field-order encoder, without the envelope or trailing LF. It is the byte
sequence to which the manifest cap applies; neither pretty JSON nor an
implementation-specific debug form counts.

History has these storage and structural caps:

- normalized TOML: 10 MiB (the existing history-entry limit);
- serialized manifest: 16 MiB;
- complete v2 envelope, including encoding overhead: 32 MiB;
- rpol units: 4096; modules per unit: 64 (the loader's existing graph cap);
- import indices per module: 4096; datasets: 65536;
- each lossless path or dataset-name byte string: 64 KiB;
- digests: exactly 32 bytes internally and 64 lowercase hex characters when
  encoded.

The writer validates structure, encodes the manifest, checks the TOML and
manifest caps, encodes the envelope, and checks the envelope cap before
creating a staging file. On read, file metadata and a 32 MiB + 1 bounded read
enforce the envelope cap **before JSON decoding**. Only after bounded JSON
decode does the reader check the TOML, serialized-manifest, path/name, and
count caps, before parsing TOML or using any manifest entry. A cap violation is
`UNREADABLE`; the JSON-inline design does not pretend component sizes are known
before envelope decode.

These are history-recording bounds, not new config-loader limits. Exceeding
one skips the history record under the best-effort invariant below; it never
turns an otherwise accepted config or reload into a rejection.

### 5. History recording is globally best-effort

History remains a rollback convenience layer, never the authority for an
already accepted config. Any provenance/history encoding, bound, directory,
ownership, orphan-cleanup, eviction, file/directory `fsync`, or rename failure
before a successful final rename publishes no record and emits a clear
warning. It never unwinds or changes an already accepted boot/SIGHUP runtime
snapshot, a successfully persisted config file, or completed runtime
reconciliation.

A failure of the final directory `fsync` after a successful rename has
ambiguous durability. It also warns without unwinding accepted state, but may
leave one complete final entry, which readers recognize normally if it is
present. It cannot leave a torn entry or exceed the 20-entry bound: the staged
file was complete and synced, and eviction was complete and directory-synced,
before the rename.

This boundary does not weaken commit-confirm durability: the v2 revert journal
must still be staged successfully **before** a confirmed candidate is allowed
to commit. A journal failure rejects that not-yet-accepted confirmed apply; it
does not roll back a previously accepted state.

### 6. Exact names, one sequence, and a hard 20-entry store

Legacy entry naming and parsing remain unchanged. A final v2 entry has exactly
this ASCII basename:

```text
v2-<seq20>-<unix-ts>-<source_sha256>.json
```

`seq20` is the unsigned sequence as exactly 20 zero-padded decimal digits;
`unix-ts` is canonical unsigned decimal (`0`, or no leading zero); and
`source_sha256` is exactly 64 lowercase hexadecimal characters. The only
recognized staging basename is the corresponding hidden form:

```text
.v2-<seq20>-<unix-ts>-<source_sha256>.json.tmp
```

No sign, whitespace, alternate padding, uppercase hex, extra suffix, or path
component is canonical. The decoded envelope's version, sequence, timestamp,
and source digest must agree exactly with the final filename.

Legacy TOML entries and v2 envelopes share one monotonically increasing
sequence. The next value is `max(recognized sequence) + 1`, checked for
overflow. A duplicate sequence is corruption: every entry carrying it is
listed as `UNREADABLE`, counts against retention, and is never a rollback or
dedupe candidate.

The store retains at most 20 logical entries across both formats. Recognized
legacy final names, exact v2 final-grammar names (including those whose
envelopes are corrupt or have an unknown version), and duplicate-sequence
entries count. Foreign or malformed basenames and exact staging-grammar names
do not count and are not listed. Ties are ordered by filename bytes only to
make listing and eviction deterministic; the tied entries remain corrupt.

Writing at the limit follows this order under the one serialized history
writer:

1. Before creating a stage, scan all exact recognized staging names. Remove
   every owned regular-file orphan and `fsync` the directory. Any removal or
   directory-sync failure refuses this record before another stage is created;
   a survivor gates each later attempt until a complete cleanup+sync succeeds.
2. Create the bounded staging file, write it, and `fsync` it.
3. Evict the oldest logical entries required to leave room, then `fsync` the
   directory. Any eviction or sync failure prevents publication.
4. Rename the staged envelope to its final name; that successful rename is the
   publication point. Then `fsync` the directory. A failure of this final sync
   warns without unwinding and leaves the complete final entry in place; its
   persistence across a crash is unknown.

Thus the directory never contains 21 published logical entries. A crash after
eviction but before publish may leave 19; that loss is preferable to violating
the hard bound. Failure after staging but before a successful final rename
triggers immediate best-effort stage removal and directory sync; if the stage
survives, the mandatory cleanup gate blocks the next attempt. A final sync
failure after rename instead may leave one complete, normally recognized final
entry; it is not removed as staging debris. Only the serialized writer may
remove a staging file, and only when its exact temporary-name grammar, current
ownership, and regular-file type all match. Readers never clean up. Foreign or
malformed basenames are ignored and never deleted. An exact staging-grammar
entry with the wrong owner or file type is an unsafe cleanup obstruction, is
neither logical nor listed, and fails the gate until the operator removes it.

The first v2 record always appends when the newest entry is legacy, even when
the normalized TOML matches. Thereafter, recording dedupes only against the
newest **valid v2** entry, and only when normalized TOML bytes and the complete
canonical source identity both match. A corrupt, unreadable, legacy, or
unknown-version newest entry never suppresses a fresh v2 record.

### 7. Integrity and filesystem boundary

The history directory is owned by the daemon uid and mode `0700`; every entry
and staging file is mode `0600` from its first byte. Creation and reads refuse
symlinks, traversal components, non-regular files, and ownership mismatches.
Existing owned directories are tightened before use; an unsafe directory
fails the history operation rather than being followed.

A v2 read verifies the bounded envelope, filename/envelope sequence and
timestamp agreement, normalized-TOML `sha256`, canonical-manifest
`source_sha256`, and all structural bounds. A readable legacy entry keeps its
existing filename/TOML digest check. Exact final-grammar names whose envelope
is malformed or unreadable -- including unknown versions, bad hashes,
duplicates, and unsafe file types -- surface as `UNREADABLE`; listing remains
available, but rollback does not.

Canonical paths reveal host layout and are sensitive. They remain inside the
owner-only envelope and may appear only in local error diagnostics on a
sensitive-read/operator surface. History list APIs, normal CLI text/JSON, and
logs do not expose the manifest or paths.

### 8. Rollback verifies once under the coordinator lock

The current partial activation stops before this final restore model: v2 and
unreadable rows are refused under the coordinator lock before a
rollback-specific payload reopen, candidate construction, planning,
persistence, events, or runtime mutation. The steps below remain the pending
external-source restore tranche; legacy TOML-only rollback is unchanged.

`rollback N` resolves and reads the exact entry while holding the existing
runtime-config coordinator lock. For v2 it then:

1. verifies the envelope's internal hashes;
2. loads normalized TOML with a detached, provenance-aware staging loader;
3. compares the newly captured manifest and `source_sha256` with the recorded
   accepted identity; and
4. passes that same validated config/provenance object into planning; only a
   plan already admissible under #1370 may proceed to mutation with it.

There is no verify-then-reread gap and no second parse that can observe another
filesystem generation. Missing, changed, differently resolved, or unreadable
external input fails before planning, persistence, or runtime mutation.

The verification load never uses dataset `Apply` mode and never reuses or
refreshes a live handle. Rpol units and datasets are compiled/read into
detached staged state. On any load or provenance mismatch, live dataset data,
generation, `last_error`, and handle identity remain unchanged, as do planner,
persister, history, journal, operational events, and runtime state. Only after
an exact match does the same detached object enter ordinary planning. The
detached policy/dataset state is verification evidence only and is never
adopted by the runtime executor.

This verified-history path does not weaken #1370. A history rollback that
contains external inputs remains behind the full-snapshot external-input fence
even after its provenance matches; verification does not create a new executor
family or an external-policy adoption exception. Ordinary native and gNMI
full-snapshot candidates likewise remain fenced. A future capability that
adopts detached external-policy state needs a separate design and production
fence proofs.

The two existing #1370 exceptions are also preserved exactly. A true no-op
with external inputs remains a no-op, and a targeted pure-`[[fib_tables]]`
transaction with unchanged external inputs remains committable because it
does not adopt the full candidate snapshot. Provenance support neither rejects
those cases nor widens the exception to another executor family.

### 9. Legacy compatibility and additive API

A readable legacy entry has provenance status `LEGACY_TOML_ONLY`. Rollback is
allowed only when its parsed TOML references no rpol units or datasets. A
legacy entry with external references fails closed with that status and an
actionable message; it is never reread and blessed as v2. History files are
never backfilled or rewritten in place.

`ConfigHistoryEntry` adds `source_sha256` and a provenance-status enum with
exact values `CONFIG_HISTORY_PROVENANCE_STATUS_UNSPECIFIED = 0`,
`CONFIG_HISTORY_PROVENANCE_STATUS_RECORDED = 1`,
`CONFIG_HISTORY_PROVENANCE_STATUS_LEGACY_TOML_ONLY = 2`, and
`CONFIG_HISTORY_PROVENANCE_STATUS_UNREADABLE = 3`. Existing `sha256` is preserved.
Valid v2 rows report `RECORDED`; legacy rows leave `source_sha256` empty;
unreadable rows expose no unverified source digest. A new client reading an old
server therefore sees `UNSPECIFIED`, never a false `RECORDED`; an old client
reading a new server ignores the additive fields. Human CLI and JSON output add
these fields without renaming or removing any existing field, and render
`UNSPECIFIED` as unknown rather than inferring provenance.

`RECORDED` means the envelope contains valid, internally verified provenance;
it does not promise that a rollback is currently possible. A successful
partial SIGHUP can retain a prior accepted dataset snapshot/provenance after a
refresh failure while recording desired normalized TOML that names the new
path. That is a valid `RECORDED` audit row. If a later rollback cannot load the
desired path and reproduce the retained accepted provenance exactly, it is
rollback-ineligible and fails closed before planning or mutation. List output
must not relabel `RECORDED` as "rollback ready."

### 10. Commit-confirm uses the same immutable provenance

A new commit-confirm journal version embeds one inline prior rollback state:
normalized TOML plus its immutable source manifest and both digests. It stores
no external source bytes or sidecars. The v2 journal deliberately omits the
legacy required `rollback_toml` field, so an older binary cannot deserialize it
as a valid old journal and fails boot closed instead of reverting without
provenance.

The v2 journal is compact UTF-8 JSON with fixed-order, `deny_unknown_fields`
structs and exactly one trailing LF. Its first bytes are the exact dispatch
prefix `{"version":2,`; the remaining top-level fields are `confirm_id`,
`deadline_unix_seconds`, `rollback_failed`, and `prior`, in that order. `prior`
contains `sha256`, `source_sha256`, `normalized_toml`, and `manifest`, using the
same encodings, field order, component caps, and canonical re-encoding check as
the history envelope. `confirm_id` retains its existing 128-character bound.

The complete v2 journal cap is 34 MiB, covering a maximum 32 MiB prior-state
envelope plus the bounded journal wrapper. Before creating a staging file, the
writer validates every component cap, encodes once, and refuses a confirmed
apply if the encoded journal exceeds that total cap. This happens before any
candidate persistence or runtime mutation. The max-valid prior-state proof must
also establish that the wrapper remains within 34 MiB; write success can never
create a journal that the same binary's boot reader rejects for size.

Boot retains the legacy v1 10 MiB preparse limit. It opens one regular,
owner-matching journal with non-following semantics, then obtains metadata,
reads the dispatch prefix, and reads the complete journal through that same
already-opened file descriptor. Only the exact v2 prefix authorizes a bounded
read of at most 34 MiB + 1; every legacy, unknown, or malformed prefix is
refused before a full read when the file exceeds 10 MiB. V2 component caps and
canonical form are checked after bounded JSON decode and before TOML parsing or
manifest use. The manifest-bearing journal inherits the history envelope's
owner-only modes and path-redaction rules.

Live abort and timeout rollback verify the prior external identity and pass
the same loaded object to the #1370-gated planning path; detached external state
is not installed. A mismatch is a rollback failure: the mutation fence stays
closed and the journal stays in place. Confirm behavior is unchanged.

Current boot has a bootstrap limitation: it fully loads the on-disk
unconfirmed candidate to discover `runtime_state_dir` before checking for a
journal. V2 external rollback must not be called shipped until bounded,
schema-minimal journal-path discovery can run before external config loading.
Once a journal is found, boot must read and verify the complete prior
config/provenance object **before** saving the candidate aside, rewriting the
config, or removing the journal. A provenance mismatch leaves both config and
journal untouched and refuses boot. A legacy journal whose rollback TOML
references external inputs likewise fails closed.

### 11. Writable downgrade after v2 publication is unsupported

An older binary does not recognize v2 history basenames. After the first v2
entry is published, starting such a binary with the same writable history
directory is unsupported: it may expose only stale legacy rows and allocate a
legacy sequence already used by v2. Release and downgrade documentation must
require stopping the daemon and either preserving the v2 directory for the new
binary or moving the complete history directory aside before the older binary
starts. A v2 commit-confirm journal already fails old-binary boot closed because
it omits required `rollback_toml`.

Re-upgrade never silently blesses a downgraded collision. The v2 scanner reads
both namespaces, marks every entry sharing a sequence `UNREADABLE`, and chooses
the next sequence from the maximum recognized value across both formats. A
collision consumes retention slots but is neither a rollback nor dedupe
candidate. There is no in-place migration or automatic deletion.

## Consequences

- History can prove that the external policy sources available at rollback are
  exactly the sources accepted with the recorded desired config.
- A semantically equal but byte-different external source becomes an auditable
  generation rather than disappearing under TOML-only dedupe.
- Rollback still cannot recover deleted policy files; operators must retain
  source artifacts separately.
- Matching provenance does not make a full-snapshot external-policy rollback
  admissible; #1370 still limits such history candidates to a true no-op or the
  existing targeted pure-FIB, unchanged-external-input exception.
- V2 coexistence costs one extra entry at first migration and may lose the
  oldest entry before a failed publish, both deliberate consequences of a
  never-over-20 crash contract.
- The loader and transaction controller must exchange one immutable validated
  object rather than reparse TOML at each layer.
- Host paths are retained as sensitive local state, increasing the importance
  of owner-only storage and bounded, non-following reads.

## Rejected alternatives

- **Archive external bytes.** This turns config history into a policy artifact
  repository, multiplies storage by IRR-scale sources, and creates restoration
  and secret-retention obligations. This ADR verifies hashes only.
- **Manifest sidecars.** They permit cross-generation pairing after a crash and
  complicate retention. The envelope is one atomic unit.
- **Rebuild provenance from compiled maps or dataset handles.** Map iteration
  loses configured/resolver order, and handles describe mutable current state,
  not the bytes accepted with the entry.
- **Reread after verification.** A second read reopens the race this design is
  meant to close. The verified object is the planning object; the #1370 fence
  still decides whether that plan is admissible.
- **Deduplicate v2 against TOML-only legacy.** Equal TOML does not prove equal
  external identity. The first v2 record is intentionally distinct.
- **Use mtimes, inode numbers, or paths alone.** They neither identify bytes nor
  survive legitimate deployment patterns.
- **Relax the external-input transaction fence.** Provenance authentication is
  useful audit evidence, but this ADR does not authorize external-policy state
  adoption through any transaction or history executor.

## Future load-bearing proof matrix

Implementation must demonstrate each named production break goes red:

1. **Capture:** rerender instead of retaining the one
   `persisted_config_document`, reread any rpol module/dataset after validation,
   build the manifest from policy maps/handles, or record failed-refresh bytes
   instead of prior accepted provenance.
2. **Roster:** reorder configured rpol units, module indices/import edges, or
   byte-sorted datasets; use a lossy path; add any excluded volatile field.
3. **Digest:** remove the domain separator or any length/count prefix; change a
   fixed integer width; redefine existing `sha256`; change raw rpol/dataset
   bytes without changing parsed semantics.
4. **Envelope encoding/bounds:** accept a noncanonical filename, JSON field
   order/form, path encoding, filename/envelope mismatch, or alternate temp
   name; treat a foreign or malformed basename as logical, listed, counted, or
   deletable; exceed each TOML/manifest/envelope or structural cap with the
   mandated pre-decode/post-decode ordering; accept a truncated/oversized
   envelope.
5. **Dedupe/migration:** dedupe first v2 against legacy, dedupe against corrupt
   newest, or suppress a byte-different semantic-equal dataset generation.
6. **Best-effort boundary:** let a pre-rename failure publish a final entry;
   make any history failure unwind or change an already accepted runtime/SIGHUP
   result or successfully persisted config; claim final post-rename sync
   failure proves absence, remove its complete final entry, or reject it when
   a later reader finds it.
7. **Ordering/retention/cleanup:** mix independent legacy/v2 sequences, accept
   duplicate sequence rollback, exceed 20 logical entries, publish after an
   eviction/sync failure, create another stage after orphan-cleanup failure, or
   let repeated failures grow staging debris. Change the cleanup+sync →
   staged-file-fsync → eviction+sync → rename/publication → final-sync
   crash states so the ambiguous final-sync window can create a torn entry or
   exceed the hard bound.
8. **Filesystem:** expose a symlink, FIFO, traversal name, wrong-owner entry, or
   group/world-readable first byte; let a reader clean up, delete a
   foreign/malformed/unsafe orphan, list an exact staging entry as logical, or
   bypass an unsafe-orphan cleanup gate.
9. **Rollback staging/race:** use dataset `Apply` mode, reuse/refresh a live
   handle, publish an event/error, verify one generation then plan/apply a
   reread generation, or change any listed live/planner/persister/history/
   journal state on load or provenance mismatch.
10. **Legacy:** roll back legacy external TOML or backfill it; reject a valid
   legacy no-external rollback.
11. **API:** remove/rename existing `sha256`, omit the additive status/digest,
    assign semantic meaning to enum zero, decode an absent old-server field as
    `RECORDED`, make an old client reject a new-server response, trust an
    unreadable digest, or expose a manifest path.
12. **Commit-confirm live:** omit prior provenance, let an older parser accept
    the v2 journal, make writer and reader v2 caps differ, accept a 34 MiB + 1
    journal or over-cap component, let a max-valid v2 journal fail its
    round-trip/boot read, mutate the candidate before an over-cap write is
    refused, or clear the fence/journal after a source mismatch.
13. **Commit-confirm boot:** touch the candidate or journal before prior-source
    verification, let a non-v2 prefix bypass the legacy 10 MiB preparse cap,
    reopen or substitute the journal path between prefix dispatch and the
    complete read, proceed on mismatch, accept legacy external rollback, or
    claim support while journal discovery still requires full candidate load.
14. **#1370 regression:** make an ordinary full-snapshot native/gNMI candidate
    or a provenance-verified history candidate with external inputs committable
    merely because provenance support exists, adopt detached verification
    state, or make a true no-op / targeted pure-FIB unchanged-external-input
    candidate fail merely because provenance support exists.
15. **Writable downgrade:** after a legacy writer creates a sequence that
    collides with retained v2, let re-upgrade resolve to either entry, omit one
    from retention, choose the next sequence from only one namespace, or
    rewrite/delete the collision instead of listing both `UNREADABLE`.

Every proof must name the production mutation it kills. Mock-only proofs of a
separately reconstructed manifest do not establish the loader-to-apply
identity contract.

## Current validation gate

V2 recording, immutable accepted-source capture, mixed listing, additive API
status/digests, filesystem hardening, and fail-closed pre-restore refusal are
shipped with executable destructive proofs. V2 restore and provenance-bearing
commit-confirm remain pending and retain the final-design proof requirements
above. Documentation consistency, source-contract review, link and terminology
checks, and `git diff --check` remain part of every tranche.
