### Added

- Max-prefix shutdown latches and inbound `block` episodes now have lasting
  alerting. The new `bgp_max_prefix_latched{peer,interface}` gauge is 1 while
  a max-prefix shutdown latch holds a peer off, until an explicit enable or a
  successful timed restart, and is seeded and reaped with the other exact
  peer-identity gauges. The shipped alert pack adds `BgpMaxPrefixLatched`
  (critical, joined to `bgp_peer_info`), which keeps firing after the
  10-minute `BgpMaxPrefixLimitExceeded` event alert resolves, and
  `BgpMaxPrefixBlocking` (warning after 5 minutes of
  `bgp_max_prefix_blocking` = 1), the inbound sibling of
  `BgpOutboundPrefixBlocking`. `rbgp doctor` warns on each blocking
  `inbound_prefix_limits[]` row as
  `peer.<scoped-address>.inbound_prefix_limit.<scope>`. The
  `bgp_peer_admin_enabled` help text and the
  [operations reference](../docs/reference/operations.md#peer-max-prefix-exceeded)
  now say that 0 also covers a max-prefix latch.
