### Fixed

- A burst of plain ROUTE-REFRESH messages for one address family from one
  peer now queues a single re-advertisement instead of one full-table
  replay per message on the shared RIB actor. A request that arrives while
  that replay is still queued is answered by it, since the replay reads the
  Loc-RIB when it starts; a request that arrives after the replay has
  started queues exactly one more. Families are never merged, ORF-carrying
  refreshes still install their filters every time, and with Enhanced Route
  Refresh one BoRR/EoRR bracket answers the coalesced requests.
  **Operator-visible:** the peer receives the family once per burst rather
  than once per message. Every message is still counted in
  `bgp_messages_received_total{type="route_refresh"}`, and each coalesced
  request logs `coalesced ROUTE-REFRESH into the replay already queued for
  this family` at debug level.
