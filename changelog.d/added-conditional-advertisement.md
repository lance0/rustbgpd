### Added

- Conditional advertisement for IPv4 and IPv6 unicast (alpha, outside the v1
  inventory). `[policy.conditional_advertisements.<name>]` defines an
  `advertise_policy` predicate, `advertise_if = "present" | "absent"`, exact
  `condition_prefixes`, an optional `condition_policy`, and a `settle_time`
  debounce (default 5 s); static neighbors attach definitions with
  `conditional_advertisements = [...]`. Matching routes are advertised to an
  attached neighbor only while the condition holds. The gate runs last,
  just before the neighbor's export chain, in every unicast export mode
  (single best, Add-Path, `per_client_best`, ORR); a suppressed route is
  withdrawn silently, and an `advertise_policy` evaluation error suppresses.
  Conditions react to route changes rather than a scan timer. Attached
  neighbors use the per-peer export path with the update-group reason
  `conditional_advertisement`, and `rbgp rib --prefix P advertised PEER
  --explain` reports `conditional_advertisement_suppressed` or
  `conditional_advertisement_eval_error`. New metrics:
  `bgp_conditional_advertisement_condition`,
  `bgp_conditional_advertisement_permitted`, and
  `bgp_conditional_advertisement_transitions_total`; a `condition_policy`
  evaluation error counts on `bgp_policy_eval_errors_total` with
  `direction="condition"`. See
  [configuration](../docs/reference/configuration.md#conditional-advertisements)
  and [ADR-0137](../docs/adr/0137-conditional-advertisement.md).
