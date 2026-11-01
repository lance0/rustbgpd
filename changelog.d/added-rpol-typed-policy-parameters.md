### Added

- `.rpol` policy parameters now have types beyond `u32`: `prefix-set`,
  `community-set` and `asn-set` (a set or dataset name), `community` (a
  standard community) and `ip` (an address), as in
  `policy customer-in(lp: u32, pfx: prefix-set, tag: community, nh: ip)`.
  A `prepend` count may also be a `u32` parameter. Arguments are checked
  against the parameter types wherever a policy is instantiated:
  `apply(p(...))`, a test `expect`, and a configured chain reference such
  as `import_policy_chain = ["customer-in(200, cust-65001)"]`. That
  includes the set's existence and kind, and the range of a parameterized
  `prepend` count or `set next-hop` address. Policies still compile to
  constants and interned sets, so there is no per-route cost. See
  [Parameters](../docs/reference/rpol-language.md#parameters).
  **Operator-visible:** a chain reference with a bad argument fails
  `rustbgpd --check` and is rejected at reload. `rbgp policy test --policy`
  and the policy dry-run RPCs accept the same call forms.
