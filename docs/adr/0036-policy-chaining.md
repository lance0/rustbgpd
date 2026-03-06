# ADR-0036: Policy Chaining + Named Policies

**Status:** Accepted
**Date:** 2026-03-04

## Context

rustbgpd's policy engine supports match + modify + filter but only allows a
single flat policy per direction per peer. Operators expect multi-policy
sequencing — reusable named policies composed in ordered chains. This is the
second-highest P2 parity gap vs GoBGP, moving policy parity from 61% to ~72%.

**Prior model:** `Policy { entries: Vec<PolicyStatement>, default_action }` with
first-match-wins semantics. One `Option<Policy>` per direction (import/export).
Per-neighbor inline policy replaces global via `.or()` fallback.

## Decision

### GoBGP-style chain semantics

Each policy in the chain is evaluated in order:

- **Permit** — accumulate route modifications, continue to next policy
- **Deny** — reject immediately, stop chain
- **After all policies** — implicit permit with accumulated modifications

This matches GoBGP's behavior and is the most intuitive model for operators
composing multiple reusable policies.

### PolicyChain type

```rust
#[derive(Debug, Clone, Default)]
pub struct PolicyChain {
    pub policies: Vec<Policy>,
}
```

`PolicyChain::evaluate()` iterates policies, accumulating modifications on
permit and short-circuiting on deny. `evaluate_chain()` is a convenience
wrapper that treats `None` as permit-all (matching existing `evaluate_policy()`
behavior).

### RouteModifications::merge_from()

Accumulates modifications across chain steps:

- **Scalars** (`set_local_pref`, `set_med`, `set_next_hop`, `as_path_prepend`):
  later policy wins (overwrite if `Some`)
- **Lists** (community/EC/LC add/remove): accumulate across policies, but
  later conflicting operations win (`add` then later `remove` leaves the
  value removed; `remove` then later `add` leaves it present)

### Named policy definitions in TOML

```toml
[policy.definitions.reject-bogons]
default_action = "deny"
[[policy.definitions.reject-bogons.statements]]
action = "permit"
prefix = "0.0.0.0/0"
ge = 8
le = 24

[policy.definitions.set-lp-customer]
[[policy.definitions.set-lp-customer.statements]]
action = "permit"
set_local_pref = 150
```

Each named policy has a configurable `default_action` (default: `"permit"`).

### Policy chains reference named definitions

```toml
# Global chains
[policy]
import_chain = ["reject-bogons"]
export_chain = ["set-lp-customer"]

# Per-neighbor chain (overrides global)
[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
import_policy_chain = ["reject-bogons", "set-lp-customer"]
```

### Backward compatibility

- Existing inline `import_policy`/`export_policy` arrays continue to work,
  wrapped in a single-element `PolicyChain`
- Inline and chain on the same neighbor/direction is a config error
- Resolution order: per-neighbor chain > per-neighbor inline > global chain >
  global inline > permit-all

### Runtime CRUD extension

Named policies and chain attachments are also exposed through the gRPC
`PolicyService`. The runtime model is intentionally narrow:

- named policy definitions are full-replace (`SetPolicy`)
- global and per-neighbor chain assignments are full-replace
- deleting a referenced named policy is rejected
- import-chain changes apply to future inbound UPDATE processing; operators use
  `SoftResetIn` when they want existing Adj-RIB-In state re-evaluated
- export-chain changes trigger outbound recomputation immediately

## Consequences

- **Policy parity with GoBGP improves from 61% to ~72%** — named definitions
  and chaining are the two biggest gaps
- **All existing configs work unchanged** — inline policies are transparently
  wrapped in single-element chains
- **Type change propagates through all crate boundaries** — `Option<Policy>`
  becomes `Option<PolicyChain>` in transport, RIB, API, and peer manager
- **19 new tests** — 10 in policy crate (merge_from + chain evaluation),
  9 in config (named policies, chain resolution, mutual exclusion)
- **gRPC CRUD reuses the same named-policy infrastructure** without changing
  chain evaluation semantics or the persisted TOML shape
