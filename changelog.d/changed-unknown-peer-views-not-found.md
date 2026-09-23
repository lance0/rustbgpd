### Changed

- Peer-scoped views now return `NOT_FOUND` (`neighbor <address> not found`)
  when they find no rows and the address names no known peer, instead of an
  empty result. This covers `ListReceivedRoutes` with a neighbor,
  `ListAdvertisedRoutes`, received-mode `ListFlowSpecRoutes`,
  `ListReceivedEvpnRoutes`, `ListAdvertisedEvpnRoutes`, `ExplainEvpnRoute`
  with `received_from` or `advertised_to`, and `GetBfdSessions` with a peer.
  A known peer is a configured neighbor, an accepted dynamic peer, or an
  address whose Adj-RIB-In still retains Graceful Restart stale routes; it
  keeps its `OK` empty result when down or silent. See
  [unknown peers](../docs/reference/api.md#unknown-peers-in-peer-scoped-views).
  **Operator-visible:** `rbgp rib received|advertised`, `rbgp evpn
  received|advertised`, `rbgp flowspec received` and `rbgp bfd show` exit 1
  with `Error: not found: neighbor <address> not found` for a mistyped or
  unconfigured address in text, `-j`, `--count` and `--json-lines` output,
  where they previously printed an empty table or a zero count and exited 0.
  API clients that treated an empty listing as "no such peer" receive the
  status instead; the Birdwatcher adapter answers such lookups with 404.
