# ADR-0119: RFC 8212 secure-default config epoch

**Status:** Accepted (representation shipped; activation proof-gated)
**Date:** 2026-07-29
**Decision recorded:** 2026-08-08

## Context

ADR-0112 shipped opt-in RFC 8212 enforcement behind
`[global].ebgp_requires_policy`, defaulting an omitted boolean to `false`.
That representation cannot distinguish an old configuration from a new
configuration whose author knowingly chose the permissive posture.

Changing the serde default to `true` would therefore reinterpret untouched
files, retained history, generated configurations, and transaction candidates.
File age, comments, formatting, release provenance, history sequence, and
whether a document looks canonical are not trustworthy freshness signals.

Implementation needs an explicit representation boundary before secure-default
activation. This ADR defines that representation and its diagnostics, and
authorizes activation only after the production-mutation proof gate below is
complete. Acceptance itself does not change route handling, activate a new
default, or supersede ADR-0112 and its M95 real-session receipt.

The representation and transaction-materialization tranches are implemented: typed raw
presence, pre-activation epoch-2 rejection, full-tuple restart pinning, shared canonical
rendering, and atomic transaction planning/receipt proofs have landed. The advisory,
migration/downgrade tooling, M95 extension, and activation remain gated by the proof plan below.

## Decision

### Root epoch and normalized posture

Add root-level `config_epoch`, outside every TOML table. Absence means epoch 1.
The only accepted explicit integer values are `1` and `2`. Zero, negative,
non-integer, unknown, and greater values are rejected; none are clamped or
treated as the newest known epoch.

Loading retains three separate facts for RFC 8212:

- raw boolean presence: `omitted`, `explicit_false`, or `explicit_true`;
- effective boolean: the value supplied to the existing ADR-0112 machinery;
- source verdict: `legacy_omission`, `explicit_false`, `explicit_true`, or,
  after a later activation only, `epoch_2_default`.

The epoch also retains raw source `omitted` or `explicit`, separately from its
effective value. Defaulting must not erase either raw-presence fact before the
source verdict is formed.

### Version matrix

The complete pre-activation and authorized activation matrix is:

| Epoch syntax | Raw `ebgp_requires_policy` | Pre-activation result | Eventual activation result |
|---|---|---|---|
| omitted (epoch 1) | omitted | `legacy_omission`, `false` | unchanged |
| omitted (epoch 1) | `false` | `explicit_false`, `false` | unchanged |
| omitted (epoch 1) | `true` | `explicit_true`, `true` | unchanged |
| `config_epoch = 1` | omitted | `legacy_omission`, `false` | unchanged |
| `config_epoch = 1` | `false` | `explicit_false`, `false` | unchanged |
| `config_epoch = 1` | `true` | `explicit_true`, `true` | unchanged |
| `config_epoch = 2` | omitted | reject | `epoch_2_default`, `true` |
| `config_epoch = 2` | `false` | `explicit_false`, `false` | unchanged |
| `config_epoch = 2` | `true` | `explicit_true`, `true` | unchanged |
| any invalid epoch | any | reject | reject |

Legacy and explicit epoch-1 omission remain effective `false` forever.
Explicit booleans are preserved in every epoch and phase. Activation may
change only the epoch-2/omitted cell from rejected to effective `true`.

Before activation, the epoch-2 omission diagnostic is exactly:

```text
config_epoch = 2 requires [global].ebgp_requires_policy = true or [global].ebgp_requires_policy = false: the RFC 8212 secure default is not activated yet (ADR-0119 gates activation on its production-mutation proofs), so epoch 2 does not infer the omitted value. This is a pending activation, not a misconfiguration; add one explicit assignment
```

The diagnostic points at the absent/required field, states that the rejection is
the pending activation gate rather than an operator mistake, and rejects startup,
`--check`, SIGHUP candidates, gRPC transactions, gNMI-generated candidates,
history rollback, and generated/imported output validation alike.

### Legacy advisory

Name the new check-time warning `rfc8212_secure_default_ready`. It appears
whenever the source verdict is `legacy_omission`, independent of policy
completeness. A fully-policed omitted config still proves the advisory; an
unpoliced config may carry both it and existing missing-policy warnings.
It reports retained mode `source=legacy_omission, effective=false`, states that
RFC 8212 enforcement remains disabled and missing chains remain permit-all,
and prints both exact edits: `config_epoch = 1` plus
`[global].ebgp_requires_policy = false` to pin that posture, or
`config_epoch = 2` plus `[global].ebgp_requires_policy = true` to prepare.

This advisory alone leaves ordinary `rustbgpd --check` at exit 0; it contributes
to the warning count that makes `rustbgpd --check --strict` exit 1. Other
warnings remain independently counted. Explicit `false` never triggers it.

### Reload, transactions, and receipts

Startup pins the normalized tuple of epoch raw/effective/source and boolean
raw/effective/source. SIGHUP may parse and diff a candidate but cannot
hot-apply any change to that tuple. It reports restart-required and retains
the complete running startup tuple.

The v1 runtime transaction planner likewise rejects an epoch, raw-presence,
source-only, or effective-value change before persistence or runtime mutation,
except for the named legacy-omission materialization transition below. That
transition is planned, persisted, and receipted atomically with the durable
mutation; every other such change is rejected without partial adoption. This
extends, rather than weakens, ADR-0112 restart pinning.

Text diffs and rejection receipts use these exact line shapes:

```text
config_epoch: raw=<omitted> effective=1 source=omitted -> raw=2 effective=2 source=explicit
[global].ebgp_requires_policy: raw=<omitted> effective=false source=legacy_omission -> raw=true effective=true source=explicit_true
```

Values vary, but labels and ordering do not. JSON uses exact top-level keys
`config_epoch` and `ebgp_requires_policy`, each containing `before` and `after`
objects with keys `raw`, `effective`, and `source`; omitted raw values are
JSON `null`. `restart_required_sections` names `config_epoch` for epoch value
or epoch-source drift and `[global].ebgp_requires_policy` for boolean
raw/source/effective drift. Representation-only changes must not disappear
from either output.

### Canonical persistence and history

One shared canonical renderer supplies durable persistence, redacted effective
config, runtime snapshot tokens, effective-config digests, and history bytes.
Its output writes an explicit root epoch and the effective RFC 8212 boolean.
Rendering, parsing, and rendering again must be byte-identical.

Boot does not rewrite the operator's main config file. An epoch-less main file
with boolean omission therefore remains byte-for-byte untouched at boot and
keeps the live `legacy_omission` verdict.

Boot and applied-config history snapshots are nevertheless canonical documents.
Any later durable mutation also rewrites the main file canonically. Materializing
epoch 1 and effective `false` changes subsequent loads from `legacy_omission`
to `explicit_false`; this named diagnostic event is the
**legacy-omission materialization transition**. It changes provenance and
advisory behavior, never effective route handling, and must appear in the
mutation receipt.

Unversioned retained history is epoch 1, never inferred fresh or secure.
Rollback uses the ordinary candidate path and canonicalizes only when the
candidate commits. A read-only history listing does not rewrite snapshots.

### Candidate paths and downgrade floor

Full-TOML gRPC candidates preserve source bytes through normalization. gNMI
mutations begin with the complete running representation, apply their targeted
edit, and submit a full candidate. Raw/source may change only through the named
materialization transition; the gNMI receipt retains and reports both tuples
rather than losing epoch, raw presence, source, or effective value silently.

The future migration tool requires an explicit operator-selected posture and
never infers intent from a freshness heuristic. It offers exact edits: pin
legacy behavior with root `config_epoch = 1` plus
`[global].ebgp_requires_policy = false`, or prepare the secure epoch with root
`config_epoch = 2` plus `[global].ebgp_requires_policy = true`. It supports a
no-write dry run, one atomic file replacement, and validated v0.61 downgrade output.

Starters and foreign-config importers may emit epoch 1; if they emit epoch 2,
they must write explicit `true`, never false or omission. Operators retain the
matrix's explicit-false choice. Only epoch-2 generated output must pass
`rustbgpd --check --strict`; epoch-1 imports may retain independent warnings.

The practical downgrade floor is the epoch-less v0.61 schema. Downgrade output
first materializes the current effective boolean, then removes `config_epoch`,
then validates the exact bytes against the v0.61 schema/loader. It refuses a
target that cannot represent or validate the posture. Downgrade necessarily
loses epoch/source provenance but never changes effective enforcement.

### Authorized activation gate

ADR-0125 records the owner decision to activate the secure default after the
representation and every production-mutation proof below land. Activation is
still an evidence gate, not a date, version inference, or automatic consequence
of accepting this ADR. No heuristic freshness signal may substitute for
`config_epoch`.

Activation changes only epoch-2 omission from invalid to effective `true`.
Epoch-less, epoch-1, and explicit boolean behavior remains frozen by the matrix.

### ADR-0112 compatibility

After normalization, the effective boolean enters the unchanged ADR-0112
resolution, reserved-deny, observability, live policy-presence transaction,
and restart-pinning paths. This ADR neither redefines explicit policy nor
weakens Route Refresh and retained-stale-state qualification.

M95 remains the required real FRR/BIRD policy-presence interop regression.
Representation work cannot claim success by replacing or bypassing it.

## Implementation and activation load-bearing proof plan

The implementation gate must make each production mutation independently red:

1. **Presence:** prove both current-model reds: collapse omitted and explicit
   false before source-verdict formation, and reject root `config_epoch` as
   unknown before epoch parsing.
2. **Matrix/invalid epochs:** change any epoch/source normalization cell,
   including explicit epoch 1 or any invalid epoch.
3. **Epoch-2 omission diagnostic:** accept omission before activation, or weaken/remove
   the exact edit requiring explicit `true` or `false`.
4. **Legacy advisory:** remove it from a fully-policed omitted config, change
   normal/strict exit behavior, or warn on explicit false.
5. **Reload/transactions:** hot-apply epoch/source/effective drift, or omit an
   epoch/source-only change from text/JSON diffs or rejection receipts.
6. **Canonicalization:** bypass the shared renderer for persistence, effective
   config, snapshot token, digest, or repeated round-trip.
7. **Candidate paths:** lose epoch/raw/source/effective semantics through
   either the gRPC or gNMI mutation path.
8. **Starters/importers:** emit epoch 2 without explicit true, or let epoch-2
   generated output stop passing strict check.
9. **History/downgrade:** treat unversioned history as fresh/true, or emit
   downgrade bytes without materialized effective bool, removed marker, and
   target validation.
10. **Activation isolation:** change any phase-matrix cell except epoch-2
    omission from invalid to effective true.
11. **Regression:** break ADR-0112 resolution/restart pinning or the M95
    policy-presence interop receipt.

Each proof must identify the named production mutation it kills. Mock-only
coverage cannot satisfy M95 or activation evidence.

## Current validation gate

Load-bearing executable proof is N/A for this docs-only decision record.
Executable proof remains a hard gate on the implementation and activation.
Current validation is structural: index consistency, matrix review, and
contradiction review against ADR-0112 and ADR-0125.

## Consequences

- A future representation release can record deliberate intent without changing the shipped default.
- Untouched legacy files and history have deterministic, permanent semantics.
- Durable canonicalization changes diagnostics at the named materialization
  transition; source-aware comparison adds state even when behavior is unchanged.
- Activation remains blocked on the named representation and production-
  mutation evidence; the owner approval is recorded in ADR-0125.
