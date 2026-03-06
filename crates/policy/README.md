# rustbgpd-policy

Minimal BGP policy engine for rustbgpd — match, modify, and filter
routes on import and export.

Part of [rustbgpd](https://github.com/lance0/rustbgpd).

## Features

- **Match criteria**: prefix (with ge/le), standard communities,
  extended communities, large communities, AS_PATH regex, AS_PATH
  length (ge/le range), RPKI validation state
- **Route modifications**: set LOCAL_PREF, MED, next-hop, add/remove
  communities (standard, extended, large), AS_PATH prepend
- **Policy chaining**: named policies with GoBGP-style chain semantics
  (permit = continue + accumulate, deny = stop)
- **`RouteContext`**: borrowed struct carrying all match inputs — no API
  churn as match criteria grow

## Key types

- **`RouteContext<'a>`** — borrowed match context (prefix, communities, AS_PATH, RPKI state)
- **`Policy`** — ordered list of `PolicyStatement`s with permit/deny actions
- **`PolicyChain`** — ordered list of `Policy`s with chain evaluation semantics
- **`PolicyResult`** — `Permit(RouteModifications)` or `Deny`
- **`evaluate_chain()`** — top-level entry point for policy evaluation

## License

MIT OR Apache-2.0
