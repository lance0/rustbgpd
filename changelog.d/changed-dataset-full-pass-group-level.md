### Changed

- A SIGHUP dataset swap that cannot be bounded to the affected routes, such
  as a change to a community set read through `route.communities in`, now
  re-evaluates each update group once and sends members only the routes
  whose export changed, sharing one encoding per group. Previously every
  member re-sent its whole table through a dirty resync, which on a full
  table held the RIB long enough for readiness to report a stalled
  export-policy transition. Receivers that also send EVPN, labeled
  unicast, FlowSpec, BGP-LS or RT-Constrain, and every receiver while a
  VPN selection is held by deferral or a conditional advertisement is
  installed, keep the per-member resync. The
  `dataset export re-evaluation complete` log event gains `full_pass`.
  See [Datasets](../docs/reference/rpol-language.md#refresh-failure-and-observability).
