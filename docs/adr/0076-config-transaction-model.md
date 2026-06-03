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
runtime-config lock and persistence acknowledgements where needed. The next
step is to expose a transaction planner first, then add small section executors
behind the same public shape.

## Decisions

1. **Separate plan and apply RPCs.** `PlanConfigTransaction` is
   `sensitive_read`; `ApplyConfigTransaction` is `operator_only`. A single RPC
   with a body-level `validate_only` flag would make authorization ambiguous and
   easy to over-grant. Planning can expose topology/diff detail but does not
   mutate; applying will mutate live runtime config once executors land.
2. **Plan is validate-only and side-effect free.** The planner parses and
   validates complete candidate TOML, compares it against the peer manager's
   live runtime config snapshot, returns the existing redacted diff rendering,
   and classifies sections into:
   - `supported_sections`: sections v1 knows how to commit once the matching
     executor slice is present.
   - `unsupported_sections`: hot-reloadable sections the transaction model
     intentionally refuses until an atomic executor exists.
   - `restart_required_sections`: sections that cannot be committed live.
3. **Optimistic snapshot token, not live config export.** Plan responses include
   a deterministic runtime snapshot token derived from normalized config
   serialization. The token is only a change detector for plan/apply races; it
   is not cryptographic and does not expose the live config document.
4. **V1 supported surface is narrow on purpose.** The planner marks
   `[[fib_tables]]` N→M/N→0 changes, `[[dynamic_neighbors]]` changes, static
   neighbor adds, and static neighbor deletes as the v1 transaction surface.
   Static neighbor modifies, policy/peer-group changes, global hot-applied
   flags, effective inheritance impacts, and all restart-required sections are
   rejected by the transaction planner until they have explicit executors.
5. **Apply entry point is reserved until executors land.** The first slice
   exposes `ApplyConfigTransaction` but returns `UNIMPLEMENTED`; follow-up PRs
   add FIB-table, dynamic-neighbor, and static-neighbor executors under the same
   method. This lets API/authz/docs stabilize before live mutation code lands.
6. **gNMI Set remains out of scope.** gNMI mutation must map to this transaction
   model rather than invent a parallel commit path, but this ADR does not
   implement OpenConfig config datastores or `Set`.

## Consequences

- `ConfigService` grows two RPCs:
  - `PlanConfigTransaction` (`sensitive_read`)
  - `ApplyConfigTransaction` (`operator_only`, initially `UNIMPLEMENTED`)
- Candidate TOML remains credential-bearing input. Audit summaries for both new
  RPCs redact the TOML body; apply summaries also avoid logging free-form
  comments verbatim.
- The transaction planner is stricter than SIGHUP. Some sections that SIGHUP can
  hot-apply are still rejected because no atomic transaction executor exists yet.
  That is intentional: transaction support means validate/commit/rollback under
  one coordinator, not merely "reload would do something."
- Follow-up executors should preserve the established pattern:
  validate candidate section against the live runtime snapshot, take the shared
  runtime-config coordinator, apply live mutation, persist with acknowledgement,
  rollback on persistence/apply failure, and only then release the lock.

See also ADR-0043 (config persistence and SIGHUP reload), ADR-0061 (unicast FIB
integration), ADR-0064 (gRPC authorization), ADR-0074 (FIB-table CRUD tier), and
`docs/GNMI.md` for the read-only gNMI boundary.
