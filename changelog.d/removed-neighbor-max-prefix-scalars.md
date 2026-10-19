### Removed

- `NeighborState` no longer carries the per-scope max-prefix scalars
  `effective_max_prefixes`, `effective_max_prefixes_ipv4`,
  `effective_max_prefixes_ipv6`, `max_prefix_headroom`,
  `max_prefix_headroom_ipv4` and `max_prefix_headroom_ipv6` (fields 43–48,
  now reserved by number and name). They duplicated the `aggregate`,
  `ipv4_unicast` and `ipv6_unicast` rows of `inbound_prefix_limits`, which
  report every finite inbound bound for every family. `rbgp neighbor <addr>
  --json` drops the same six keys, and the human detail view drops its
  "Max Prefixes" block in favour of the existing "Inbound Prefix Limits"
  block. `prefixes_received_ipv4` and `prefixes_received_ipv6` are unchanged
  and are now required numbers in the
  [v1 neighbor-detail JSON floor](../docs/reference/v1-stable-contract.md).
