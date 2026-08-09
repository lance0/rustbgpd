# Config Knob Contributor Guide

Adding a config knob is a user-visible contract. The parser accepting TOML is
only the first step; the reload class, persistence behavior, docs, and tests must
move with it.

## Required checklist

1. **Schema**
   - Add the field to the appropriate struct in `src/config/schema.rs`.
   - Keep `#[serde(deny_unknown_fields)]` on config structs. Do not add catch-all
     maps for convenience.
   - Choose an explicit default. Prefer a semantic default in the schema type
     over "missing means magic" in later runtime code.

2. **Validation**
   - Add validation in `src/config/validation.rs` for ranges, mutually exclusive
     fields, unsupported combinations, and ownership boundaries.
   - Add a negative test in `src/config/tests/mod.rs` that proves bad input is
     rejected with an operator-actionable error.

3. **Reload / transaction class**
   - Decide whether the knob is live, restart-required, parse-time rejected, or
     transaction-supported.
   - Update `docs/reload-matrix.md`.
   - If the field is on `Neighbor` or `PeerGroupConfig`, update
     `RELOAD_MATRIX_NEIGHBOR_FIELDS` or `RELOAD_MATRIX_PEER_GROUP_FIELDS` in
     `src/config/tests/mod.rs`. Those tests intentionally fail when a field is
     accepted by the schema but missing from the reload matrix.
   - For load-bearing live-vs-restart claims, extend
     `reload_matrix_pins_load_bearing_field_classes`.

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
   - Update `docs/CONFIGURATION.md`.
   - Update `docs/reload-matrix.md`.
   - Update `docs/API.md` / CLI docs when the knob is exposed through an RPC or
     command.
   - If the knob changes a product boundary, update `README.md`,
     `docs/LIMITATIONS.md`, or the relevant cookbook.

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
