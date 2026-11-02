### Changed

- `.rpol` rejects well-known community names in every binding form: policy
  and function parameters, `let` bindings (including function bodies), and
  `for` variables. Sets and datasets use the same reservation. RFC-assigned
  future aliases `NOPEER`, `ACCEPT_OWN`, `LLGR_STALE`, `NO_LLGR` and
  `STANDBY_PE` are reserved without adding literal support. See
  [Reserved names](../docs/reference/rpol-language.md#parameters).
- Retire the unreachable `.rpol` evaluation-error kinds `overflow`,
  `underflow` and `clamp-inverted` from the Rust `EvalErrorKind` enum,
  in-language `expect` vocabulary and `bgp_policy_eval_errors_total{kind}`
  vocabulary. The metric-consumer check now requires each remaining kind
  to have a runtime emitter; compile-time diagnostics and synthetic test
  values do not count.
