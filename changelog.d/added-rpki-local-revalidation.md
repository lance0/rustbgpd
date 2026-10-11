### Added

- Opt-in RFC 9324 local re-evaluation: with `local_revalidation = true` in
  `[rpki]`, sessions whose import policy matches RPKI or ASPA state keep their
  pre-policy IPv4/IPv6 unicast input, and a VRP or ASPA change re-runs import
  policy locally for the covered routes instead of sending inbound Route
  Refresh to every dependent peer. Each session retains at most 65,536
  validation rejects; beyond that it falls back to Route Refresh until the
  session resets. FlowSpec families and IRR dataset swaps keep Route Refresh.
  See [local re-evaluation](../docs/reference/configuration.md#local-re-evaluation-rfc-9324).
  **Operator-visible:** `bgp_validation_import_refreshes_total` gains the
  `revalidated_locally` and `fallback_refresh` outcomes; the default
  behaviour is unchanged.
