# rustbgpd-policy

BGP policy engine for rustbgpd — the TOML match/modify/filter core, the
`rpol` policy language (ADR-0096), and the attribution/explain surfaces
the daemon's `explain` features build on.

Part of [rustbgpd](https://github.com/lance0/rustbgpd).

## Features

- **Match criteria**: prefix (with ge/le), standard communities,
  extended communities, large communities, AS_PATH regex, AS_PATH
  length (ge/le range), RPKI validation state, ASPA validation state,
  neighbor-set membership, route source type, EVPN route type,
  next-hop, and LOCAL_PREF / MED range (ge/le)
- **Route modifications**: set LOCAL_PREF, MED, next-hop, add/remove
  communities (standard, extended, large), AS_PATH prepend
- **Policy chaining**: named policies with GoBGP-style chain semantics
  (permit = continue + accumulate, deny = stop)
- **`RouteContext`**: borrowed struct carrying all match inputs — no API
  churn as match criteria grow

## rpol policy language (ADR-0096)

The crate also ships the `.rpol` policy-language frontend and its
compilation pipeline:

- **`rpol`** — parser for the `.rpol` source language (modules,
  imports, in-language `test` blocks)
- **`ir`** — typed intermediate representation policies compile into
- **`compile`** — `.rpol` → typed IR → engine `Policy` compilation
- **`datasets`** / **`sets`** — named prefix-set / community-set /
  AS-set datasets referenced from policy terms

## Key types

- **`RouteContext<'a>`** — borrowed match context (prefix, communities, AS_PATH, RPKI state)
- **`Policy`** — ordered list of `PolicyStatement`s with permit/deny actions
- **`PolicyChain`** — ordered list of `Policy`s with chain evaluation semantics
- **`PolicyResult`** — struct of `action: PolicyAction` (`Permit` / `Deny`) plus `modifications: RouteModifications` (empty on `Deny`)
- **`evaluate_chain()`** — top-level entry point for policy evaluation
- **`evaluate_chain_with_attribution()`** / **`PolicyEvaluation`** —
  evaluation plus the deciding policy/statement attribution backing
  import explain (ADR-0073)
- **`explain_chain_statements()`** — per-statement trace of a chain
  against one route (`ChainStatementTrace` / `StatementAttribution`)
- **`PolicyHitCounters`** — live per-term hit counters behind
  `rbgp policy stats`

## License

MIT OR Apache-2.0
