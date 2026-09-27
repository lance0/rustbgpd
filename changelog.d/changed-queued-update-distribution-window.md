### Changed

- The RIB now distributes a run of already-queued unicast UPDATE messages in
  one outbound pass instead of one pass per message, following RFC 4271
  Appendix F.1. When a message finishes ingest, the next queued unicast
  route message joins its distribution window; the window closes when no
  such message is waiting, before any other update (session up or down,
  End-of-RIB, route refresh, configuration, queries on the update channel),
  or at a bound of 256 messages, 4,096 ingested routes, 1,024 changed
  prefixes or 5 ms. Nothing waits for input, so an isolated UPDATE is
  distributed as before. Loc-RIB, route events and ingest counters still
  advance per chunk. A prefix that changes several times inside one window
  is advertised once, in its final state, and export-policy counters count
  that one evaluation. In a manager benchmark with 1,000 route-server
  clients, 64 queued one-prefix UPDATEs took about 2.4 ms of RIB work
  instead of 141 ms with a plain update group, and 4.7 ms instead of 147 ms
  with a per-client-best group.
