# ADR-0076: Config Transaction Model Foundation

**Status:** Accepted
**Date:** 2026-06-03

## Context

rustbgpd has several runtime config mutation paths today:

- SIGHUP reload validates a full TOML candidate and hot-applies the sections the
  reload path supports.
- gRPC CRUD methods mutate targeted runtime state (`[[fib_tables]]`, static
  neighbors, dynamic-neighbor ranges, policies, and peer groups) and persist
  accepted changes through the config bridge.
- `DiffRuntimeConfig` validates a candidate TOML and reports what SIGHUP would
  apply or require a restart for.

Those paths are useful, but they are not a daemon-wide transaction model:
operators cannot yet ask the daemon to validate a full candidate, receive a
stable optimistic-concurrency token, and then commit only the sections whose
executors can apply atomically under the shared runtime-config coordinator.
That matters for automation, because a future gNMI `Set` implementation and
bulk CLI/API changes need one set of invariants rather than per-method behavior.

The existing runtime serialization work is the foundation: FIB-table CRUD,
dynamic-neighbor CRUD, static-neighbor CRUD, and SIGHUP already use a shared
runtime-config lock and persistence acknowledgements where needed. The
transaction model exposes one planner and apply shape, then adds bounded
section executors behind that public contract.

## Decisions

1. **Separate plan and apply RPCs.** `PlanConfigTransaction` is
   `sensitive_read`; `ApplyConfigTransaction` is `operator_only`. A single RPC
   with a body-level `validate_only` flag would make authorization ambiguous and
   easy to over-grant. Planning can expose topology/diff detail but does not
   mutate; applying mutates only sections with an explicit executor.
2. **Plan is validate-only and side-effect free.** The planner parses and
   validates complete candidate TOML, compares it against the peer manager's
   live runtime config snapshot, returns the existing redacted diff rendering,
   and classifies sections into:
   - `supported_sections`: sections v1 knows how to commit.
   - `unsupported_sections`: hot-reloadable sections the transaction model
     intentionally refuses until an atomic executor exists.
   - `restart_required_sections`: sections that cannot be committed live.
3. **Optimistic snapshot token, not live config export.** Plan responses include
   a runtime snapshot token: a keyed hash of the normalized config serialization
   under a per-process key seeded when the peer manager starts. The token is a
   change detector for plan/apply races, not a live config document. It is
   **keyed** rather than a plain hash because the canonical serialization
   includes secret-bearing fields (`md5_password`, `tcp_ao.key`): an unkeyed
   hash handed to a `sensitive_read` caller would be an offline oracle for
   brute-forcing a weak secret (hash a guess, match the token). The key never
   leaves the process, so a caller cannot recompute the digest for a guessed
   secret; the full config (secrets included) is still hashed, so a secret
   rotation invalidates a stale plan. Consequence: **tokens are process-local** —
   a token does not survive a daemon restart, and a client holding a pre-restart
   token must re-plan (apply returns `FAILED_PRECONDITION` on mismatch).
4. **V1 supported surface is narrow on purpose.** The planner marks
   `[[fib_tables]]` N→M/N→0 changes, `[[dynamic_neighbors]]` changes, static
   neighbor add/delete/modify changes, and catalog-only policy/peer-group/global
   named-chain changes as the v1 transaction surface. "Catalog-only" means the
   diff has no `effective_neighbor_impact`: no existing peer's resolved runtime
   import/export policy or inherited peer-group state changes. The impact check
   spans both static `[[neighbors]]` and `[[dynamic_neighbors]]` ranges — an edit
   that reshapes the resolved policy a dynamic range inherits is rejected too,
   because SIGHUP live-reconciles established dynamic peers and a catalog
   snapshot does not. Policy/peer-group edits with live neighbor impact, global
   hot-applied flags, and all restart-required sections are rejected until they
   have explicit executors.
5. **Apply execution is one pure runtime family at a time.** V1 commits pure
   full-set `[[fib_tables]]`, pure full-set `[[dynamic_neighbors]]`, static
   `[[neighbors]]` add/delete/modify, or catalog-only snapshot candidates. It
   re-plans under the shared runtime-config coordinator, rejects mixed-family or
   unsupported candidates without mutation, stages the peer-manager snapshot,
   applies live runtime state when the family has one, persists the exact
   accepted candidate with an acknowledgement, and rolls back on every
   post-stage failure. Static-neighbor modifies use the same delete/re-add
   session-reconfigure semantics as SIGHUP, but with transaction rollback rather
   than best-effort reconcile. Catalog-only transactions have no live peer
   runtime mutation: they stage and persist the snapshot so future peers or
   later neighbor transactions can reference the catalog objects.
6. **gNMI Set remains out of scope.** gNMI mutation must map to this transaction
   model rather than invent a parallel commit path, but this ADR does not
   implement OpenConfig config datastores or `Set`.

## Consequences

- `ConfigService` grows two RPCs:
  - `PlanConfigTransaction` (`sensitive_read`)
  - `ApplyConfigTransaction` (`operator_only`)
- Candidate TOML remains credential-bearing input. Audit summaries for both new
  RPCs redact the TOML body; apply summaries also avoid logging free-form
  comments verbatim.
- `rustbgpctl config plan` and `rustbgpctl config apply` are thin clients over
  the same RPCs. They print redacted daemon summaries by default and stable JSON
  when `--json` is set.
- The transaction planner is stricter than SIGHUP. Some sections that SIGHUP can
  hot-apply are still rejected because no atomic transaction executor exists yet.
  That is intentional: transaction support means validate/commit/rollback under
  one coordinator, not merely "reload would do something."
- V1 apply is intentionally single-family: a candidate that changes
  `[[fib_tables]]` and `[[dynamic_neighbors]]` together, for example, is
  rejected even though each family is independently supported.
- The FIB-table executor requires the ADR-0061 reconciler to already be running;
  starting the FIB subsystem from an empty startup config remains
  restart-required. This matches SIGHUP and targeted FIB CRUD semantics.
- Dynamic-neighbor transactions replace the full range set from the candidate
  TOML. Static-neighbor transactions support add/delete/modify; modifies rebuild
  the session like SIGHUP and preserve disabled / graceful-shutdown intent.
- Catalog-only policy/peer-group/global-chain transactions stage reusable config
  objects before static neighbors or dynamic ranges depend on them. A policy,
  neighbor-set, peer-group, or global-chain edit that changes the effective
  runtime policy of any static neighbor or dynamic range remains rejected until a
  rollback-capable live policy executor exists.
- Follow-up executors should preserve the established pattern:
  validate candidate section against the live runtime snapshot, take the shared
  runtime-config coordinator, apply live mutation, persist with acknowledgement,
  rollback on persistence/apply failure, and only then release the lock.
- SIGHUP reload also takes that coordinator and reads the live peer-manager
  runtime snapshot after acquiring it, so a reload queued behind a committed
  transaction compares the operator's TOML against the transaction-updated
  baseline.
- If rollback itself fails, apply returns `INTERNAL` with both the original
  apply/persistence error and the rollback failure context. Silent rollback
  failure is not an acceptable transaction outcome.

See also ADR-0043 (config persistence and SIGHUP reload), ADR-0061 (unicast FIB
integration), ADR-0064 (gRPC authorization), ADR-0074 (FIB-table CRUD tier), and
`docs/GNMI.md` for the read-only gNMI boundary.
