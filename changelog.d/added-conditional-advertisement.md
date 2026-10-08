### Added

- Conditional advertisement state metrics (ADR-0137):
  `bgp_conditional_advertisement_condition{name,state}` publishes each
  definition's observed condition (`present`, `absent`, or `unknown`) as a
  state set, `bgp_conditional_advertisement_permitted{name,advertise_if}`
  its applied gate, and `bgp_conditional_advertisement_transitions_total{name}`
  each change to the applied state. A `condition_policy` evaluation error
  counts on `bgp_policy_eval_errors_total` with `direction="condition"`. The
  daemon still refuses configurations that define conditional advertisements
  until export enforcement ships, so these series do not appear yet; see
  [the operations reference](../docs/reference/operations.md#conditional-advertisement-state).
