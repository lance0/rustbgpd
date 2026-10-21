### Upgrade notes

- Fast external failover is on by default. Directly connected eBGP sessions
  (static link-local neighbors and numbered single-hop peers on a connected
  subnet) now drop as soon as their link loses carrier, goes down, is removed,
  or loses the session's source address, and their routes are withdrawn rather
  than kept under Graceful Restart. Previously they stayed up until the hold
  timer or BFD expired. A flapping link now flaps those sessions; dampen carrier
  at the link (for example the bond's `downdelay`), or keep the previous
  behavior with `fast_external_failover = false` in `[global]`, a peer group, or
  a neighbor.
