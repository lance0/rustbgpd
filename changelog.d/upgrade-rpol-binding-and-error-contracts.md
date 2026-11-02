### Upgrade notes

- **Rename bindings that use well-known community names.** A policy or
  function parameter, `let` or `for` variable, set or dataset named
  `NO_EXPORT`, `NO_ADVERTISE`, `NO_EXPORT_SUBCONFED`, `BLACKHOLE`,
  `GRACEFUL_SHUTDOWN`, `OV_VALID`, `OV_NOT_FOUND`, `OV_INVALID`, `NOPEER`,
  `ACCEPT_OWN`, `LLGR_STALE`, `NO_LLGR` or `STANDBY_PE` now causes a compile
  error. Previously, a local name such as `NO_EXPORT` could mean its bound
  value in `set med NO_EXPORT` but the community literal in
  `add community NO_EXPORT`. Rename the binding and its intended references,
  for example to `tag`, while retaining `NO_EXPORT` where the literal is
  intended. No runnable repository example needs migration.
- **Remove retired arithmetic error expectations and dashboard selectors.**
  `expect p == error overflow`, `error underflow` and `error clamp-inverted`
  now cause compile errors with a migration hint. Expect the verdict and
  saturated modifications instead, for example `accept with med 4294967295`.
  Remove `kind="overflow"`, `kind="underflow"` and `kind="clamp-inverted"`
  selectors for `bgp_policy_eval_errors_total` from alerts and dashboards;
  there is no replacement error series for saturated arithmetic. Rust
  consumers must remove the corresponding `EvalErrorKind` match arms.
  Invalid literal-only arithmetic remains a compile error. A file with a
  reserved binding or retired expectation is rejected by `rbgp policy
  check`, `rustbgpd --check`, startup and reload, regardless of
  `require_passing_tests`; a rejected reload keeps the running policy.
