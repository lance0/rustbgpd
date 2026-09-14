# Config Knob Contributor Guide

> **Document class: CURRENT.** This maintained page reflects the project as it is now; dated sections remain bounded to their stated scope.

Adding a config knob is a user-visible contract. The parser accepting TOML is
only the first step; the reload class, persistence behavior, docs, and tests must
move with it.

## Required checklist

1. **Schema**
   - Add the field to the appropriate struct in `src/config/schema.rs`.
   - Fields shared by `Neighbor` and `PeerGroupConfig` belong in the private
     `define_neighbor_and_peer_group_configs!` inventory. Declare the field
     name and type once, and provide both structs' field documentation and
     attributes there. Keep neighbor-only fields explicit in the generator.
   - Keep `#[serde(deny_unknown_fields)]` on config structs. Do not add catch-all
     maps for convenience.
   - Choose an explicit default. Prefer a semantic default in the schema type
     over "missing means magic" in later runtime code.
   - `Neighbor` and `PeerGroupConfig` have manual `Debug` impls in
     `src/config/schema.rs` that redact credentials. Add the field there,
     redacted if it carries a secret.
   - Resolve it through `src/config/parse.rs` (policy and family parsing) or
     `src/config/resolution.rs` (inherited per-peer resolution) when the
     runtime consumes a resolved value rather than the raw field.
   - Regenerate the published schema with
     `cargo run --bin rustbgpd -- --dump-config-schema > docs/reference/rustbgpd.schema.json`;
     `config_json_schema_committed_copy_is_fresh` fails on a stale copy.

2. **Validation**
   - Add validation in `src/config/validation.rs` for ranges, mutually exclusive
     fields, unsupported combinations, and ownership boundaries.
   - Add a negative test in the topic module under `src/config/tests/` (for
     example `neighbor_validation.rs`, `datasets.rs`, or `telemetry.rs`) that
     proves bad input is rejected with an operator-actionable error.

3. **Reload / transaction class**
   - Decide whether the knob is live, restart-required, parse-time rejected, or
     transaction-supported.
   - Update `docs/reference/reload-matrix.md`.
   - If the field is on `Neighbor` or `PeerGroupConfig`, add it to
     `RELOAD_MATRIX_NEIGHBOR_FIELDS` or `RELOAD_MATRIX_PEER_GROUP_FIELDS` in
     `src/config/tests/mod.rs`. These lists are maintained by hand, not derived
     from the schema: the tests in `src/config/tests/diff.rs` fail only when a
     listed field is missing from the matrix, so a new field left off the list
     passes silently.
   - For load-bearing live-vs-restart claims, extend
     `reload_matrix_pins_load_bearing_field_classes`.
   - Classify the field for diffs and reloads in `src/config/mod.rs`:
     `config_field_impact` (the hot-applied / session-reset / restart-required
     annotation), `neighbor_runtime_equal` (a neighbor field it omits never
     registers as changed), and `resolved_session_change` (hot update in place
     versus session replacement). A new top-level family also needs a
     `SighupReloadFamilies` entry and a decision in `classify_sighup_reload`
     (generation, sequential, or rejected route).
   - A restart-required global field that SIGHUP must not advance belongs in
     `pin_unreconciled_daemon_runtime_fields` in `src/reload.rs`.

4. **Runtime behavior**
   - Wire the field through the runtime model that consumes it.
   - If a live reload applies it, add or extend a reload/converger test that
     proves the running actor sees the new value.
   - If it is restart-required, add a `--diff` / classification test showing it
     is reported as restart-required rather than silently ignored.

5. **Persistence**
   - If the knob can be set through gRPC/gNMI/CLI, make sure the config persister
     writes the same TOML shape the parser accepts.
   - Add a round-trip test for persisted config when the knob is mutable.

6. **Docs**
   - Update `docs/reference/configuration.md`.
   - Update `docs/reference/reload-matrix.md`.
   - Update `docs/reference/api.md` / CLI docs when the knob is exposed through an RPC or
     command.
   - If the knob changes a product boundary, update `README.md`,
     `docs/reference/limitations.md`, or the relevant cookbook.

7. **Receipts**
   - For protocol-affecting knobs, add an interop or proof receipt when the
     behavior cannot be trusted from unit tests alone.
   - Record deliberate deferrals in an ADR or roadmap entry instead of hiding
     them in code comments.

## Common mistakes

- **Schema-only knobs.** A field parses but never reaches the actor that should
  consume it. Add a runtime or converger test.
- **Undocumented reload behavior.** Operators need to know whether SIGHUP is
  enough. The reload-matrix tests are there to force the decision.
- **Config/API drift.** A field can be set through TOML but not persisted through
  the corresponding gRPC/gNMI mutation path, or vice versa.
- **Implicit unsafe adoption.** Kernel/dataplane knobs need explicit ownership
  and foreign-state rules. Preserve fail-closed behavior when attribution is
  missing.
- **Over-broad examples.** Prefer minimal examples that load through
  `rustbgpd --check`; long explanatory prose belongs in cookbooks or ADRs.

## Review prompt

When reviewing a config-knob PR, ask:

```text
Where is the schema field documented, validated, classified for reload,
persisted if mutable, consumed by runtime code, and tested against docs drift?
```
