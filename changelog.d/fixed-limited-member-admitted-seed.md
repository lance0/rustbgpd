### Fixed

- An outbound prefix limit installed by a reload on an update-group member
  that had not yet received the group's routes, such as a member whose first
  session established during a graceful-restart selection hold while its
  outbound queue was full, now starts from the prefixes that member was
  actually sent. It used to start from the group's desired routes, so a
  route deleted before it ever reached the member stayed counted after the
  hold released, although the member never received it and no withdrawal
  was owed. The routes on the wire were correct.
  **Operator-visible:** for that member, the advertised prefix count, the
  outbound prefix limit usage, `bgp_outbound_prefix_usage` and
  `bgp_rib_adj_out_prefixes` no longer keep a deleted route, and the route
  no longer takes one of the limit's slots.
