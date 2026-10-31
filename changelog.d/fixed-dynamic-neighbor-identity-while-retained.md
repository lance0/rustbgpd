### Fixed

- Keep an idle `[[dynamic_neighbors]]` peer's RIB identity, and its
  `dynamic_neighbor_limit` slot, while graceful restart may still hold routes
  on either side: the GR or LLGR stale routes we retain for it, and, when its
  last session made it our helper, ours it may retain, for our restart time
  plus LLGR stale time plus a hold time. Its automatic removal used to delete
  it at once, which purged the retained routes and gave a reconnect a new
  identity: the reconnect no longer resumed the restart, and its ORF-gated
  initial End-of-RIB went out before the gated table, so the peer dropped the
  routes it kept. A reconnect from the address in that window is now the same
  neighbor; one that never returns is deleted once both retentions lapse.
  Removing its range, a rollback without the range, or a static neighbor at
  the address still deletes it at once.
- An interface-only neighbor's binding retirement no longer forgets that the
  ended session may still hold our routes stale, so a rebind to the same
  endpoint keeps its ORF-gated End-of-RIB behind the table.
