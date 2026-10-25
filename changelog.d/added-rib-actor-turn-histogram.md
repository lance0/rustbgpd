### Added

- `bgp_rib_actor_turn_duration_seconds{kind}` times every RIB actor turn,
  the synchronous handling of one inbound RIB message, labelled by message
  kind (`routes`, `peer_up`, `peer_down`, `query`, and nine more). Every
  series is exported at zero from startup, and a new message type cannot
  build until it is assigned a kind. A turn of 200 ms or longer logs one
  `slow RIB actor turn` WARN with the kind, duration, and the peer, route
  or member count where one applies, at most once per 10 seconds with a
  count of suppressed turns. See the
  [operations reference](../docs/reference/operations.md#key-metrics-to-watch).
  **Operator-visible:** per-kind p50 and p99 now show which message kind
  holds the actor, for example serial peer-down teardown, without matching
  log timestamps.
