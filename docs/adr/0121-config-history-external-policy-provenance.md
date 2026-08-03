# ADR-0121: Config-history external-policy provenance

**Status:** Accepted, implemented
**Implementation:** v2 history restore and provenance-bearing commit-confirm v2 shipped
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
rows now retain the accepted manifest and source digest. Restore therefore
requires the loader to revalidate that identity. The native transaction
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

The restore model is active. Unreadable rows refuse under the coordinator lock;
legacy rows declaring external inputs refuse without external file access.
Verified v2 restore follows the ordered steps below.

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

A v2 commit-confirm journal embeds one inline prior rollback state: normalized
TOML plus its immutable source manifest and both digests. It stores no external
source bytes or sidecars. It deliberately omits the v1 `rollback_toml` field,
so an older binary cannot deserialize it as a valid old journal and fails boot
closed instead of reverting without provenance.

The v2 journal is compact UTF-8 JSON with fixed-order, `deny_unknown_fields`
structs and exactly one trailing LF. Its first bytes are the exact dispatch
prefix `{"version":2,`; the remaining top-level fields are `confirm_id`,
`deadline_unix_seconds`, `rollback_failed`, and `prior`, in that order. `prior`
contains `sha256`, `source_sha256`, `normalized_toml`, and `manifest`, using the
history envelope's encoding, field order, component caps, and canonical
re-encoding check. `confirm_id` retains its 128-character bound.

The complete journal cap is 34 MiB. The writer checks every component and the
encoded total before any candidate persistence or runtime mutation. The boot
reader reads at most 34 MiB + 1 byte solely to detect oversize input and rejects
anything larger than 34 MiB; it then enforces component caps before TOML parsing
or manifest use. A max-valid write must round-trip through that reader.

#### Boot authority is adjacent to the launch config

Candidate-derived discovery is forbidden for v2: the unconfirmed candidate is
exactly the input boot must not trust. At process start, the daemon retains one
stable **lexical launch identity** for the positional config argument. It makes
the path absolute against the original working directory, rejects any remaining
`..` (`ParentDir`) component, and may remove `.` only where that preserves path
semantics. It never normalizes through a symlinked ancestor or follows the final
component. Reload, persistence, or a changed working directory cannot rebase
this identity.

The sole v2 pending-authority locator is:

```text
<absolute lexical CONFIG_PATH>.commit-confirm-locator.json
```

Its presence means a v2 confirmed commit is pending. Boot checks it before
opening, sizing, parsing, or otherwise trusting the candidate config. There is
no global candidate-config size cap in this design; the existing loader caps
still apply after pending-state resolution.

The locator is compact UTF-8 JSON with exactly one trailing LF and these fields
in this order: `version` (exactly `2`), `confirm_id`, `journal_path`,
`config_target`, `prior_sha256`, and `prior_source_sha256`. The paths are
lossless absolute Unix paths encoded as the manifest path object; each decoded
path is at most 64 KiB. Digests are exactly 64 lowercase hexadecimal
characters, and `confirm_id` retains its 128-character bound. The complete
locator is at most 512 KiB. Unknown or duplicate fields, noncanonical JSON,
alternate encodings, trailing bytes, or a byte-different compact re-encoding
plus LF are invalid.

`journal_path` names the exact v2 journal. `config_target` is the lossless real
target to which the lexical config path resolved when the confirmed commit was
accepted. If the lexical final component still resolves at boot, it must resolve
to that same target; retargeting a config symlink never redirects a pending
revert. If the final component is a dangling symlink, boot uses `lstat` and
`readlink` on that leaf itself, derives its lossless absolute target identity
relative to the pinned real parent, and requires it to equal `config_target`.
A retargeted dangling link refuses. When the original recorded target is
missing, boot restores to that target and places any saved `.unconfirmed`
candidate adjacent to it. Retargeting an ancestor or launching with a different
lexical `CONFIG_PATH` is unsupported. The two digests must equal the journal's
embedded prior state before any prior-source load.

The locator, journal, and their stages are regular files owned by the daemon
uid and mode `0600` from their first byte. For a writer or any present v2
object, their real parent directories are pinned by descriptor, owned by that
uid, and neither group- nor world-writable. Establishing locator absence alone
pins the real parent descriptor but applies no v2 ownership or mode policy:
absence carries no authority, so ordinary pre-v2 launch paths remain valid.
Any present locator immediately enters the full private-parent checks, and a
writer cannot publish there unless the parent meets that contract. Reads and
cleanup are descriptor-relative with `O_NOFOLLOW`:
open once, `fstat`, bound, and read through that same descriptor. No check may
be followed by a path reopen. The lexical config parent and journal parent may
differ, so each has its own pinned descriptor and durability sync.

The only staging names are `<journal>.tmp` and `<locator>.tmp`. Each is created
in the same pinned directory as its final with owner-only mode and `O_EXCL`;
neither cross-directory staging nor an alternate suffix is recognized.

#### Writer admissibility and crash order

A confirmed writer may start only while it still owns the stable lexical launch
identity, the locator, journal, and resolved config-target parents pass the full
owner-private checks above, and the final locator is absent. Exact owned regular
`0600` staging or journal residue may be removed
and its directory synced before proceeding; an unsafe, ambiguous, differently
owned, non-regular, noncanonical, or unremovable residue refuses the apply.
Cleanup may touch only the exact journal and locator final basenames and the two
exact staging basenames above, under the same descriptor, owner, type, and mode
checks. A published locator is authority, not residue. No wider directory scan
or suffix match is permitted.

Publication order is load-bearing:

1. encode and validate the journal and locator completely;
2. stage, write, `fsync`, rename the journal, then `fsync` its directory;
3. stage, write, `fsync`, rename the locator, then `fsync` its directory; and
4. only then persist and apply the unconfirmed candidate.

A crash before locator publication leaves the prior config authoritative; the
exact journal is safe residue and cannot trigger a revert. A crash after
locator publication invokes the verified prior-state path even if candidate
persistence had not begun. Any publication failure cleans only exact safe
residue when that cleanup can be proven; otherwise it refuses the candidate
and leaves diagnostics for operator repair.

#### Six boot states

Locator presence takes precedence; legacy fallback is considered only when the
locator is absent.

| Locator | Journal selected by that discovery lane | Boot result |
|---|---|---|
| absent | absent | Load the candidate normally. |
| absent | valid v1 | Preserve the existing v1 bounded boot revert. |
| absent | v2 | Never revert; durably clean exact safe residue and proceed, or refuse if it is unsafe. |
| present | absent | Refuse boot; pending authority has lost its journal. |
| present | v1 or non-v2 | Refuse boot; the locator authorizes only its exact v2 journal. |
| present | matching valid v2 | Verify prior provenance, then revert before candidate load. |

An invalid, unsafe, oversized, mismatched, or unreadable locator occupies the
`present` rows and fails closed; it never falls back to v1. A valid locator
whose journal path, `confirm_id`, digests, config target, or journal contents do
not match does not open candidate contents or mutate candidate, backup, or
pending files; launch-target metadata may already have been inspected to bind
authority. V1 discovery keeps its existing 10 MiB preparse cap and exact format,
and a v1 prior containing external inputs remains refused. A v2 journal without
a locator is never boot revert authority. It is either prepublication residue
or residue after the locator's terminal removal. An exact canonical, owned,
regular `0600` journal
may be removed and its directory synced before boot proceeds; unsafe,
malformed, or unremovable residue refuses boot. Locator-absent plus
journal-present never reconstructs or re-arms pending state.

#### Revert and terminal cleanup

Boot reads and verifies the locator, complete journal, prior TOML, and prior
external provenance before saving the candidate aside, rewriting config, or
removing pending state. Live abort and timeout use the same loaded immutable
object and #1370-gated planner; detached external state is not installed. A
mismatch keeps the mutation fence closed and leaves pending state untouched.

For boot, abort, and timeout, the verified prior config is durably restored
while both files remain. They then remove the locator and `fsync` its parent;
only durable locator absence is terminal. Confirm does not load or verify prior
sources: a matching `confirm_id` durably removes and syncs the locator first,
making the accepted candidate permanent. This intentionally strengthens and
changes shipped v1 durability semantics in ADR-0076: after locator unlink and
parent `fsync` are durable, confirm is successful. A later journal-cleanup
failure can only warn; it cannot fail the RPC or re-arm pending state.

For every terminal path, journal removal follows durable locator removal and is
best-effort. Failure warns but cannot fail the completed RPC, re-arm the fence,
or revive pending state. A retry that finds the locator already absent must
still `fsync` its parent before reporting terminal success, then may clean the
exact safe journal residue. A locator unlink or parent-`fsync` failure is
nonterminal: the running daemon retains its mutation fence and reports failure.
Boot then applies the six-row table rather than guessing. A crash before the
terminal point leaves locator authority and repeats or fails closed; a crash
after it leaves only non-authoritative cleanup residue.

Ordinary logs and viewer surfaces expose only a bounded failure class.
Operator and `sensitive_read` status may include the bounded `confirm_id` and
redacted path **roles**, never values. No API, log, or normal CLI output renders
`journal_path` or `config_target` decoded from the locator, even locally. A
startup diagnostic may name only the deterministic locator path derived from
the launch argument. Digests and prior source paths are never logged.

Writable downgrade remains unsupported until both the locator and locator-free
v2 journal residue are absent: old binaries do not understand either format.
This pending-state rule is separate from the v2 history-directory move-aside
rule below. Re-upgrade accepts only the exact states above; it never blesses or
migrates a residue produced by a downgrade. A live v1 pending
transaction must be confirmed, aborted, timed out, or boot-reverted before an
upgrade. Rewriting it out of band is unsupported; v2 never converts a live v1
journal and never dual-writes v1 plus v2 pending state.

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
- V2 commit-confirm boot authority no longer depends on parsing unconfirmed
  candidate contents, but it adds one config-adjacent owner-only locator and
  makes writable downgrade unsupported until both the locator and locator-free
  v2 journal residue are absent.

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
- **Discover v2 through `runtime_state_dir` in the candidate.** A candidate can
  redirect or prevent discovery of the state that must decide whether that
  candidate is authoritative. Only the launch-config-adjacent locator breaks
  that dependency without imposing a global candidate cap.

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
    round-trip/boot read, mutate the candidate before the journal and locator
    are each published and directory-synced, accept an occupied/unsafe locator
    or residue, stage under another name/directory or without `O_EXCL`, clean a
    suffix match instead of an exact staging/final name, or clear the fence
    after a source mismatch.
13. **Commit-confirm boot authority:** discover v2 from candidate
    `runtime_state_dir`, open/size/parse the candidate before checking the
    locator, accept a locator over 512 KiB or path over 64 KiB, use a lossy or
    relative path, accept or normalize through a `ParentDir`, accept
    noncanonical JSON, follow a symlink, reopen after a check, tolerate an
    unsafe parent or changed resolved target, fail to inspect a dangling leaf,
    accept a retargeted dangling link, fail to restore a missing recorded
    target, place `.unconfirmed` elsewhere, tolerate a locator/journal field
    mismatch, or expose a locator-carried path/digest.
14. **Commit-confirm state/cleanup:** let an absent locator authorize v2 or
    refuse exact safe cleanup residue, let a present/invalid locator fall back
    to v1, reject exact legacy v1 when no locator exists, bypass the legacy
    10 MiB preparse cap, touch candidate or pending files before prior
    verification, remove the locator before durable abort/timeout/boot restore,
    treat confirm as terminal before locator removal+sync, preserve the v1 rule
    that journal cleanup can fail a durably terminal v2 confirm, skip the
    locator-dir sync after `NotFound`, fail/re-arm after post-terminal journal
    cleanup fails, proceed on mismatch, accept legacy external rollback,
    convert a live v1 journal, or dual-write pending formats.
15. **#1370 regression:** make an ordinary full-snapshot native/gNMI candidate
    or a provenance-verified history candidate with external inputs committable
    merely because provenance support exists, adopt detached verification
    state, or make a true no-op / targeted pure-FIB unchanged-external-input
    candidate fail merely because provenance support exists.
16. **Writable downgrade:** after a legacy writer creates a sequence that
    collides with retained v2, let re-upgrade resolve to either entry, omit one
    from retention, choose the next sequence from only one namespace, or
    rewrite/delete the collision instead of listing both `UNREADABLE`.

Every proof must name the production mutation it kills. Mock-only proofs of a
separately reconstructed manifest do not establish the loader-to-apply
identity contract.

## Current validation gate

V2 recording, immutable accepted-source capture, mixed listing, additive API
status/digests, filesystem hardening, verified v2 history restore, and
provenance-bearing commit-confirm v2 are shipped with executable destructive
proofs. The production writer emits only v2 pending state. Locator-free v1
state remains a fail-closed compatibility lane; a live v1 transaction must
terminate before upgrade, and v2 never converts or dual-writes it. The
locator/journal publication order, exact caps and canonical
encoding, descriptor-relative filesystem checks, six-state boot matrix,
same-object live rollback, boot-before-candidate restore, terminal locator
ordering, and post-terminal warning-only residue cleanup remain regression
gates. Documentation-only design changes have no executable red proof.
Documentation consistency, source-contract review, link and terminology
checks, and `git diff --check` remain part of every tranche.
