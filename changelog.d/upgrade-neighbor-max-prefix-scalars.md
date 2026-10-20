### Upgrade notes

- API and `rbgp neighbor --json` consumers that read `effective_max_prefixes*`
  or `max_prefix_headroom*` must read `inbound_prefix_limits[]` instead: the
  `stage = "accepted"` row whose `family` is `aggregate`, `ipv4_unicast` or
  `ipv6_unicast` carries the same bound as `limit` and the same remaining
  capacity as `headroom`. A missing row means that bound is unlimited, or
  that the peer-session snapshot is stale. `rbgp doctor` and the Birdwatcher
  adapter example now read only the rows, so they no longer recognise a bound
  reported by a daemon older than 0.69.0.
