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

Those paths were useful, but they did not provide a daemon-wide transaction
contract for automation. ADR-0076 adds that contract: operators can validate a
full candidate, receive a stable optimistic-concurrency token, and then commit
only the sections whose executors can apply atomically under the shared
runtime-config coordinator. That matters because a future gNMI `Set`
implementation and bulk CLI/API changes need one set of invariants rather than
per-method behavior.

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
   token must re-plan (apply returns `FAILED_PRECONDITION` on mismatch). The
   token is not a cryptographic commitment, proof-of-knowledge, lease, or
   authorization credential; if a future API needs those properties it must use a
   wider cryptographic MAC/commitment and a new token version.
4. **V1 supported surface is narrow on purpose.** The planner marks
   `[[fib_tables]]` N→M/N→0 changes, `[[dynamic_neighbors]]` changes, static
   neighbor add/delete/modify changes, catalog-only
   policy/neighbor-set/peer-group/global named policy-chain changes, and a
   bounded live-policy impact family as the v1 transaction surface.
   "Catalog-only" means the diff has no `effective_neighbor_impact`: no static
   neighbor's or dynamic range's resolved runtime import/export policy or
   inherited peer-group state changes. A
   live-policy impact is committable only when the impact is a pure resolved
   import/export `PolicyChain` move — no transport-config reshape and no
   peer-group reassignment. The impact check spans both static
   `[[neighbors]]` and `[[dynamic_neighbors]]` ranges. Established dynamic peers
   retain the canonical longest-prefix-match range that accepted them so the
   live-policy executor can target only the affected dynamic sessions. Global
   hot-applied flags, restart-required sections, dynamic-range session reshapes,
   and peer-group edits that require session reconfiguration remain rejected
   until they have explicit executors. The redacted diff reports each effective
   impact as `kind: policy_chain` or `kind: session_reshape` so the planner and
   later executors do not infer committability from a lossy boolean.
5. **Apply execution is one pure runtime family at a time.** V1 commits pure
   full-set `[[fib_tables]]`, pure full-set `[[dynamic_neighbors]]`, static
   `[[neighbors]]` add/delete/modify, catalog-only snapshot candidates, or the
   bounded live-policy impact family. It re-plans under the shared runtime-config
   coordinator, rejects mixed-family or unsupported candidates without mutation,
   stages the peer-manager snapshot, applies live runtime state when the family
   has one, persists the exact accepted candidate with an acknowledgement, and
   rolls back on every post-stage failure. Static-neighbor modifies use the same
   delete/re-add session-reconfigure semantics as SIGHUP, but with transaction
   rollback rather than best-effort reconcile. Catalog-only transactions have no
   live peer runtime mutation: they stage and persist the snapshot so future
   peers or later neighbor transactions can reference the catalog objects. The
   live-policy impact executor stages the snapshot, re-applies each affected
   static neighbor's or accepted dynamic peer's resolved import/export chains to
   the live session through the peer manager, captures prior chains as a rollback
   token, persists with an acknowledgement, and restores live chains plus the
   snapshot on persistence failure. Dynamic peers are selected by their stored
   accepted-range attribution, not by re-running longest-prefix-match against a
   possibly changed matcher. Re-evaluating an affected Established peer's
   already-received routes under the new import policy is driven by Route Refresh
   (RFC 2918) — rustbgpd does not keep a pre-policy soft-reconfiguration copy —
   so a live-policy impact transaction **requires that every impacted
   Established peer negotiated the Route Refresh capability**; if one did not,
   the apply is rejected and rolled back cleanly (the refresh during rollback is
   best-effort, so a non-RR peer yields a single clear rejection, not a compound
   rollback error).
6. **Confirmed-commit is singleton and process-local.** A caller can set
   `confirm_id` on `ApplyConfigTransaction` to enter commit-confirmed mode.
   The candidate still goes through the same plan/apply/persist executor first;
   if it commits, the daemon records the pre-commit runtime snapshot and starts a
   confirm timer (default 600 seconds, maximum 86400). `ConfirmConfigTransaction`
   with the same `confirm_id` makes the committed candidate permanent.
   `AbortConfigTransaction` rolls back immediately by re-applying the captured
   pre-commit snapshot through the same transaction executor. If the timer
   expires, the daemon performs the same rollback automatically. V1 allows only
   one pending confirmed transaction daemon-wide. While one is applying or
   pending, persisted runtime config mutators are rejected with
   `FAILED_PRECONDITION` so timeout rollback cannot overwrite a later ad hoc
   config write. Pending confirmed state is not persisted across daemon restart;
   after restart, clients must re-plan and re-apply. The confirm timer is
   in-memory, so a restart during the confirm window leaves the already-committed
   candidate live (effectively confirmed-by-restart) and the auto-revert never
   fires: the timer is a safety net against a bad-but-running config, not against
   a daemon crash.
7. **gNMI Set remains out of scope.** gNMI mutation must map to this transaction
   model rather than invent a parallel commit path, but this ADR does not
   implement OpenConfig config datastores or `Set`.

## Consequences

- `ConfigService` grows five RPCs:
  - `PlanConfigTransaction` (`sensitive_read`)
  - `ApplyConfigTransaction` (`operator_only`)
  - `ConfirmConfigTransaction` (`operator_only`)
  - `AbortConfigTransaction` (`operator_only`)
  - `GetConfigTransactionStatus` (`sensitive_read`)
- Candidate TOML remains credential-bearing input. Audit summaries for both new
  RPCs redact the TOML body; apply summaries also avoid logging free-form
  comments verbatim. Confirm/abort/status summaries include only bounded
  correlation/status fields.
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
  objects before static neighbors or dynamic ranges depend on them. If the same
  policy, neighbor-set, peer-group, or global-chain edit changes only a static
  neighbor's or dynamic range's resolved import/export `PolicyChain`, the
  live-policy impact executor can commit it by re-applying the resolved chains
  in place. Edits that reshape peer transport/session config, reassign peer
  groups, or change a
  dynamic range's resolved policy remain rejected until their own rollback-capable
  live executors exist.
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
- Commit-confirmed rollback uses the same executor as ordinary
  `ApplyConfigTransaction`, so it inherits the same validation, persistence, and
  rollback reporting. This also means abort or auto-revert can fail if the
  current runtime snapshot no longer matches the post-commit snapshot token; the
  pending mutation fence is what keeps ordinary runtime config writes from
  creating that mismatch. A failed abort or auto-revert clears the pending fence
  and records a failed lifecycle status so operators can inspect the failure and
  issue a new corrective transaction.

See also ADR-0043 (config persistence and SIGHUP reload), ADR-0061 (unicast FIB
integration), ADR-0064 (gRPC authorization), ADR-0074 (FIB-table CRUD tier), and
`docs/GNMI.md` for the read-only gNMI boundary.
