# ADR-0130: Identity-Conditional External-Policy Transaction Fence

**Status:** Accepted
**Date:** 2026-09-01

## Context

Since #1370, the v1 config-transaction classifier rejects any transaction
whose selected executor would adopt the full candidate snapshot while either
side of the diff declares external policy inputs (`[policy] rpol_files` or
`[policy.datasets]`). The hazard that fence closes is real: external policy
bytes live outside the candidate TOML, outside the optimistic
`runtime_snapshot_token`, and outside the rollback payload. Every v1 executor
except the targeted `[[fib_tables]]` path adopts the full candidate snapshot,
so an unrelated neighbor or catalog mutation could silently adopt `.rpol` or
dataset content that was never part of the transaction.

The fence, however, is **presence**-conditional. Any deployment that uses
`.rpol` at all — including the shipped IXP route-server profile
(`examples/route-server/config.toml`, `rpol_files = ["hygiene.rpol"]`) —
loses the entire transactional quartet (plan, apply, commit-confirm,
rollback) for even a trivial neighbor-description edit, and is pushed to the
file-edit-plus-SIGHUP workflow for every change.

[ADR-0121](0121-config-history-external-policy-provenance.md) built the
machinery this decision stands on: every accepted config carries a v2 source
manifest (per-`.rpol`-module and per-dataset canonical path, byte length,
SHA-256, and import edges) and a domain-separated `source_sha256`; capture
happens during the same read that produces the running content and is never
re-read afterwards. ADR-0121 §8 used that machinery for verified history
rollback but explicitly kept the presence fence, deferring any
external-policy adoption capability to "a separate design and production
fence proofs". This ADR is that design.

## Decision

Make the full-snapshot clause of the external-input fence
**identity**-conditional instead of presence-conditional.

The classifier input gains an `ExternalInputsIdentity` verdict with two
values: `Unverified` (the default everywhere) and `VerifiedUnchanged`. The
full-snapshot rejection clause now fires when external inputs are present
**and** the verdict is `Unverified`. The `rpol_changed` / `datasets_changed`
clauses are untouched: an actual change to the declared external roster or
compiled `.rpol` content rejects regardless of the verdict.

Only the config-transaction plan path can produce `VerifiedUnchanged`, and
only by an actual comparison:

1. The candidate load on that path captures every external source it reads —
   the same read that produces the compiled `.rpol` registry and parsed
   dataset handles — and condenses the capture into a domain-separated
   digest over the ADR-0121 v2 manifest's external frames (document hash
   excluded). Two manifests share this digest exactly when substituting one
   document hash into the other would reproduce the same `source_sha256`,
   i.e. when the external inputs are byte-identical.
2. The peer manager compares that digest against the accepted snapshot's
   manifest (the ADR-0121 accepted authority watch). Equality means the
   content the executor would adopt **is** the accepted content, so the
   silent-adoption hazard cannot arise; the transaction is allowed.
3. Anything else — no captured digest, no accepted authority, or any
   mismatch — stays `Unverified` and rejects exactly as before. A missing or
   unreadable external file at plan time fails the candidate load itself.

### The verified candidate adopts no detached state

On `VerifiedUnchanged`, the planner immediately re-attaches the running
external state into the candidate before anything can adopt it: the
candidate's freshly compiled `.rpol` units are replaced by the running
registry's shared storage, and its freshly parsed dataset handles are
replaced by the live handles. The fresh reads serve as verification evidence
only — exactly the discipline ADR-0121 §8 required of verified rollback.
The committed runtime therefore keeps the very dataset handles that future
SIGHUP refreshes swap in place; no second policy or dataset generation
enters the runtime, and dataset generations and statistics are preserved.

This is why the change is **not** the "detached external-policy state
adoption" ADR-0121 §8 warned about. That warning concerned adopting external
content whose identity is not the accepted identity. Here the only content
ever adopted is proven byte-identical to the accepted content, and the
adopted in-memory state is the running state itself.

### TOCTOU chain

What is captured when, and what covers each side:

- **Plan RPC** (`PlanConfigTransaction` / stream variant): the peer manager
  parses the candidate TOML with capture, verifies, classifies. Advisory
  only; nothing is adopted.
- **Apply** runs under the runtime-config coordinator lock, which also
  serializes SIGHUP reload and every other persisted runtime mutation — the
  accepted authority cannot advance mid-apply, and a pending confirm window
  additionally rejects SIGHUP outright. The apply executor never adopts the
  plan RPC's capture. It performs its own captured parse of the candidate
  TOML and plans twice through the real planner: the authoritative plan
  re-parses the TOML (fresh capture, fresh verification), and the typed plan
  verifies the exact `Config` object the executor will stage — the object
  whose own captured digest rode in with it, and the object into which the
  live handles are re-attached on success. The typed plan's committed
  candidate must byte-match the authoritative plan's or apply fails with
  `FAILED_PRECONDITION`. An external file edited between any two of these
  reads produces a digest mismatch (rejected) or a candidate-changed
  precondition failure — there is no verify-then-adopt gap.
- **The optimistic token** covers what it always covered: the accepted
  runtime config plus the RIB snapshot identity on the accepted side. It
  never hashed external bytes and still does not; external bytes are covered
  by the digest comparison performed at apply time under the coordinator
  lock, against an accepted manifest that the same lock holds still.
- **History rollback** keeps its ADR-0121 §8 chain unchanged
  (`load_retained` + retained-manifest verification, failing closed with
  `FAILED_PRECONDITION`) and then passes through this classifier like any
  apply. Its verdict compares the retained row's external identity against
  the **current** accepted identity, so rolling back across an
  external-content change remains rejected — reload the sources first.

### Mid-window edits

- **Runtime auto-revert and abort** re-apply the in-memory
  `prior_snapshot: Arc<AcceptedConfigSnapshot>` captured before the
  candidate committed. Capture never re-reads external sources, and the
  revert candidate's identity is seeded from that snapshot's own manifest —
  so an external file edited between apply and auto-revert cannot inject
  content into the revert, and because SIGHUP is fenced while the window is
  pending, the accepted external identity is unchanged and the revert still
  classifies committable.
- **Boot revert** re-loads the journaled prior sources from disk and
  verifies them against the retained manifest and `source_sha256`, failing
  closed ("journaled prior sources are unavailable or changed") on any
  drift. Unchanged.

### Scope

gNMI Set full-snapshot candidates remain **presence-fenced**. The gNMI
bridge plans and applies without external-input verification (the plain,
non-capturing candidate load), so external inputs present means rejected
there even when the on-disk sources are unchanged — the #1370 posture,
deliberately preserved. The two existing #1370 exceptions are also
preserved: a true no-op remains `NOOP`, and a targeted pure-`[[fib_tables]]`
transaction remains committable because it never adopts the full snapshot.

Every non-verifying classifier caller defaults to `Unverified`, so a missed
or future call site fails safe (presence-fenced), never open.

## Consequences

- Deployments with `.rpol` / dataset files regain plan, apply,
  commit-confirm, and rollback for every supported transaction family, as
  long as the external sources on disk are byte-identical to the accepted
  ones. Any drift — including semantically-equal rewrites such as added
  comments — rejects with the existing external-inputs reason; the deploy
  path for changed external content remains files-plus-SIGHUP.
- No external bytes are archived, no new executor family is added, and the
  rejection reason string is unchanged.
- A new domain string (`rustbgpd.config-external-sources.v2`) separates the
  external-roster digest from the full `source_sha256`; both are derived
  from the same v2 manifest frames.
- The peer manager now holds a receiver of the accepted-config authority
  watch. Daemons without a config file have no authority and keep the
  presence fence everywhere.
