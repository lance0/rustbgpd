### Added

- `.rpol` adds `else if` chains and nested `if` statements, which were
  previously excluded. `if a { ... } else if b { ... } else { ... }` runs
  exactly one branch, and a branch that only modifies continues with the
  rest of the policy. That is the IOS-XR RPL `elseif` behavior a term per
  branch could not express without hand-written negations. An `if` body
  may hold nested `if` statements up to four levels deep, like loops; an
  `else if` chain of any length counts as one level. Branches lower to the
  existing first-match terms, each guarded by its path condition, so
  explain names (`term.n`), hit counters and coverage are unchanged in
  kind. Existing files parse, format and compile exactly as before. See
  [Policies, terms, and evaluation order](../docs/reference/rpol-language.md#policies-terms-and-evaluation-order).
  **Operator-visible:** `rbgp policy check` gains the `unreachable-branch`
  lint for a branch whose constant-folded guard can never match, and a
  bare `--deny-lints`, which denies every lint, now includes it.
