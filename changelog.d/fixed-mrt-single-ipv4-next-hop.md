### Fixed

- MRT dumps, the shutdown warm checkpoint and BMP Loc-RIB announcements now
  carry exactly one `NEXT_HOP` for an IPv4 unicast route learned over BGP.
  The encoders added the route's next hop beside the received `NEXT_HOP`
  that the RIB keeps, so each entry carried the attribute twice, and after
  an import `next-hop self` the second copy was the stale received value.
  **Operator-visible:** with
  [`warm_cache_checkpoint_on_shutdown`](../docs/reference/configuration.md)
  enabled, a daemon holding such a route never published a checkpoint (the
  shutdown log reported `warm bundle MRT recovery discarded N path
  attributes`); it now does. MRT files and BMP collectors receive one `NEXT_HOP`, the
  route's post-import-policy next hop. MRT files written by earlier releases
  still hold the duplicate; readers that follow RFC 7606 keep the first copy,
  which was already the post-policy next hop.
