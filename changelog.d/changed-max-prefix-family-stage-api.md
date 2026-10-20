### Changed

- `InboundPrefixLimitState` names each inbound max-prefix bound with `family`
  and `stage`, the labels of the `bgp_max_prefix_*` metrics, instead of a
  single `scope` string (field 1, now reserved by number and name). `family`
  is `aggregate` or a canonical family label, and `stage` is `accepted` or
  `received`. A row now joins its metric series without rebuilding the
  label. The `max_prefix_warning` session event detail, the
  `inbound_prefix_limits[]` rows of `rbgp neighbor --json`, the "Inbound Prefix
  Limits" block of the human detail view, and the `rbgp doctor` check name
  `peer.<address>.inbound_prefix_limit.<family>.<stage>` use the same
  spelling. See the [API reference](../docs/reference/api.md).
