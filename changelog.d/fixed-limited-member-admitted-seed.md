### Fixed

- An outbound prefix limit installed by a reload on an update-group member
  that had not yet received the group's latest routes, such as a member
  whose first session established during a graceful-restart selection hold
  while its outbound queue was full, now starts from the prefixes that
  member was actually sent. It used to start from the group's desired
  routes, so a route deleted before it ever reached the member stayed
  counted after the hold released, although the member never received it
  and no withdrawal was owed. The routes on the wire were correct. The
  reload's limit check now measures the same prefixes, so a limit below
  what such a member still holds, including a route whose withdrawal has
  not reached it yet, is refused before anything changes instead of being
  installed over its limit.
  **Operator-visible:** for that member, the advertised prefix count, the
  outbound prefix limit usage, `bgp_outbound_prefix_usage` and
  `bgp_rib_adj_out_prefixes` no longer keep a deleted route, and the route
  no longer takes one of the limit's slots. A reload that sets a lower
  outbound maximum than the member currently holds fails with the existing
  over-limit refusal and leaves the running limits unchanged; retry after
  the member's queue drains.
