### Fixed

- Keep an idle `[[dynamic_neighbors]]` peer's RIB identity, and its
  `dynamic_neighbor_limit` slot, while graceful restart may still hold routes
  on either side: the GR or LLGR stale routes we retain for it, and, when its
  last session made it our helper, ours it may retain, for our restart time
  plus our LLGR stale time when both sides advertised LLGR, plus a hold time.
  A session that ended with a Hard Reset, or a NOTIFICATION without the
  RFC 8538 N bit, leaves nothing of ours held. Its automatic removal used to
  delete it at once, which purged the retained routes and gave a reconnect a
  new identity: the reconnect no longer resumed the restart, and its
  ORF-gated initial End-of-RIB went out before the gated table, so the peer
  dropped the routes it kept. A reconnect from the address now becomes the
  same neighbor once an OPEN from the same AS validates, without a second
  `PEER_ADDED`; a connection that never reaches Established leaves the
  retention unchanged; one that never returns is deleted, with `PEER_REMOVED`, once both
  retentions lapse. Retention checks share one RIB query and never wait in
  the peer manager. At the limit, a neighbor kept only while it may hold our
  routes gives its slot to a new address. Removing its range, a rollback
  without the range, or a static neighbor at the address still deletes it,
  and a staged transaction's ranges wait for its commit or rollback.
- A reconnect to a retained dynamic neighbor whose OPEN comes from a
  different AS is a new speaker: it gets a new RIB identity, and the GR or
  LLGR routes retained for the last one, and that one's hold of ours, are
  purged with the old identity.
- An interface-only neighbor's binding retirement no longer forgets that the
  ended session may still hold our routes stale, so a rebind to the same
  endpoint keeps its ORF-gated End-of-RIB behind the table.
