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
   and mixed policy/session effective impact remain rejected until they have
   explicit executors. Static peer-group/session reshape impact is committable
   when every affected peer is a concrete static neighbor: the transaction
   executor rebuilds those sessions with captured prior configs. The redacted
   diff reports each effective impact as `kind: policy_chain` or
   `kind: session_reshape` so the planner and executors do not infer
   committability from a lossy boolean.
5. **Apply execution is one pure runtime family at a time.** V1 commits pure
   full-set `[[fib_tables]]`, pure full-set `[[dynamic_neighbors]]`, static
   `[[neighbors]]` add/delete/modify, catalog-only snapshot candidates, the
   bounded live-policy impact family, or static peer-group/session reshape
   impact. It re-plans under the shared runtime-config coordinator, rejects
   mixed-family or unsupported candidates without mutation, stages the
   peer-manager snapshot, applies live runtime state when the family has one,
   persists the exact accepted candidate with an acknowledgement, and rolls back
   on every post-stage failure. Static-neighbor modifies and static
   peer-group/session reshapes use the same delete/re-add session-reconfigure
   semantics as SIGHUP, but with transaction rollback rather than best-effort
   reconcile. Catalog-only transactions have no
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
   rollback error). The direct gRPC catalog mutators (`SetPolicy` and the other
   policy / neighbor-set / chain commands) commit their peer fan-out through
   this same capturing snapshot primitive, so a mid-fanout failure there also
   restores the already-updated peers instead of leaving split-brain chains.
6. **Confirmed-commit is singleton and process-local.** A caller can set
   `confirm_id` on `ApplyConfigTransaction` to enter commit-confirmed mode.
   The candidate still goes through the same plan/apply/persist executor first;
   if it commits, the daemon records the pre-commit runtime snapshot and starts a
   confirm timer (default 600 seconds, maximum 86400). `ConfirmConfigTransaction`
   with the same `confirm_id` makes the committed candidate permanent.
   `AbortConfigTransaction` rolls back immediately by re-applying the captured
   pre-commit snapshot through the same transaction executor. The gNMI
   `CommitSetRollbackDuration` extension can reset the pending timer to a new
   positive whole-second duration; it overwrites the timer rather than appending
   time. If the timer expires, the daemon performs the same rollback
   automatically. V1 allows only one pending confirmed transaction daemon-wide.
   While one is applying or pending, persisted runtime config mutators are
   rejected with `FAILED_PRECONDITION` so timeout rollback cannot overwrite a
   later ad hoc config write. Pending confirmed state is not persisted across
   daemon restart; after restart, clients must re-plan and re-apply. The confirm
   timer is
   in-memory, so a restart during the confirm window originally left the
   already-committed candidate live (effectively confirmed-by-restart) and the
   auto-revert never fired. *Superseded by the 2026-07-03 amendment below: a
   restart inside the confirm window now reverts at boot via an on-disk
   journal.*
7. **gNMI Set is an adapter, not a second commit model.** gNMI mutation must
   map to this transaction model rather than invent a parallel commit path. The
   gNMI service can normalize Set requests, redact Set audit summaries, and
   delegate to a daemon-owned bridge hook. The first supported slice translates
   static, numbered BGP neighbor config leaves into candidate TOML and commits
   through this ADR-0076 controller. The standard gNMI commit-confirmed
   extension maps to the same confirm / abort lifecycle; gNMI does not get a
   separate pending-transaction store. This ADR does not define a full
   OpenConfig config datastore.

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
- `rbgp config plan` and `rbgp config apply` are thin clients over
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
  in place. Static peer-group/session reshapes can also commit when every
  affected peer is a concrete static neighbor: the executor reconfigures those
  sessions and uses captured prior peer configs for rollback. Dynamic-range
  session reshapes and mixed policy/session effective impacts remain rejected
  until their own rollback-capable live executors exist.
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
  creating that mismatch. A failed abort or auto-revert keeps the transaction
  pending with a failed lifecycle status (`ABORT_FAILED`/`AUTO_REVERT_FAILED`):
  the mutation fence stays closed and the revert journal is retained, because
  the daemon could not restore the pre-transaction state and a later-accepted
  mutation would otherwise be clobbered by the journal's boot revert. Operators
  resolve it by retrying the abort, confirming the candidate, or restarting
  (boot revert). Likewise, a confirmed apply that fails without proof of a
  terminal outcome — lost persistence acknowledgement, post-persist
  finalization failure, or compound rollback failure — retains the journal and
  fences all further config mutations until a restart boot-reverts.

See also ADR-0043 (config persistence and SIGHUP reload), ADR-0061 (unicast FIB
integration), ADR-0064 (gRPC authorization), ADR-0074 (FIB-table CRUD tier), and
`docs/GNMI.md` for the current gNMI Set supported-path matrix.

## Amendment (2026-07-03): durable commit-confirm — boot-time revert journal

Decision 6 originally held the confirm timer and the pre-commit rollback
snapshot in memory only, so a daemon restart inside the confirm window made the
unconfirmed candidate permanent (confirmed-by-restart) — the exact config a
commit-confirmed deploy exists to protect against (one bad enough to take the
daemon down) was the one the mechanism could not revert. That hole is closed:

- **Journal at commit.** Before the confirmed candidate commits, the daemon
  atomically persists (write temp file, fsync, rename, fsync directory) a
  revert journal — `confirm_id`, an informational pre-apply deadline, and the
  full pre-commit config TOML snapshot — to
  `<runtime_state_dir>/commit-confirm-journal.json`. If the
  journal cannot be written, the confirmed apply is refused up front; a
  confirm window never runs unprotected. Confirm deletes the journal (and the
  confirm fails, keeping the fence and timer armed, if deletion fails — a
  leftover journal must never boot-revert an explicitly confirmed config).
  Abort and timeout auto-revert delete it after a successful rollback; a
  FAILED rollback deliberately retains it so the next boot repairs what the
  running process could not.
- **Start the live window after commit.** The public Unix deadline and the
  in-process monotonic timer are minted together only after a committable Apply
  succeeds, so validation, persistence, and runtime fan-out do not consume the
  operator's requested confirmation window. The already-published journal is
  not rewritten: its deadline is publication metadata, and boot recovery below
  is unconditional.
- **Boot-time revert, unconditionally.** Before adopting the on-disk config,
  startup checks for the journal. If an unconfirmed journal exists, the daemon
  boots from the journal's pre-transaction config, restores it to the config
  file, saves the unconfirmed candidate aside as `<config>.unconfirmed`, and
  logs a loud ERROR plus a startup-banner notice. The revert fires regardless
  of how much confirm time remained: the operator's confirming session and the
  in-memory timer died with the old process, and resuming a half-elapsed timer
  in a fresh process invites split-brain between the operator's view and the
  daemon's. This matches NETCONF (RFC 6241 §8.4) semantics, where loss of the
  session that issued a confirmed commit cancels it.
- **Fail closed on a damaged journal.** Any journal that exists is treated as
  an unconfirmed window that must be reverted. If the journal is torn or
  unreadable, or its embedded previous config is unusable, that revert cannot
  be completed — the daemon then refuses to boot with a message naming both
  the journal and the config file, and touches neither. It never silently
  proceeds with a possibly-unconfirmed candidate. (The atomic
  write-then-rename makes a torn journal a should-not-happen case: a crash
  during the write leaves either no journal or a complete one.)
- **Config-plane only.** No RIB manager involvement; the boot revert happens
  in `main` before the runtime starts, and the journal lives entirely in the
  transaction controller (`src/confirm_journal.rs`).

Proven by real-binary SIGKILL tests in `tests/commit_confirm_binary.rs`:
SIGKILL mid-window then restart boots the previous config with the candidate
saved aside; confirm-then-SIGKILL retains the new config with no pending
authority; in-process timeout auto-revert consumes the pending state; and a
torn locator-free v1 journal still refuses boot naming both legacy files.

ADR-0121 subsequently superseded the v1 **discovery, payload, and
terminal-cleanup contract** above. Its v2 writer stores the immutable accepted
prior snapshot, including its external-source manifest and digests, in the
owner-private runtime-state journal, then publishes an owner-private locator
adjacent to the stable lexical launch-config path. The locator is the sole v2
pending authority and is checked before candidate contents are parsed. Boot and live
rollback verify the same accepted prior snapshot, but the execution paths are
distinct: boot directly adopts the verified accepted object before opening
candidate contents or mutating candidate/backup, while live abort and timeout
reuse it through the ordinary #1370-gated planner and apply path. Launch-target
metadata may be inspected while binding boot authority. Abort, timeout, and
boot restore durably restore while both files remain, then remove and sync the
locator. Confirm starts with that locator removal. Exact journal cleanup after
the terminal point is warning-only. That amendment wrote only v2. The
locator-free v1 reader is a fail-closed compatibility lane; a live v1
transaction must terminate before upgrade and v2 never converts or dual-writes
it. Before downgrade, both the v2 locator and locator-free v2 journal residue
must be absent; v2 config history separately requires its complete directory
to be moved aside.

The later disk-backed v3 implementation supersedes only v2's pending-authority
storage. Production writes v3 raw prior, compact metadata, and a config-adjacent
locator; v1 and v2 remain frozen recovery readers. The live confirmation-window
and unconditional boot-revert decisions above apply unchanged across all three
storage formats.
