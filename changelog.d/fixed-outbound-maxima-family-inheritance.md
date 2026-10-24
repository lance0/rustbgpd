### Fixed

- A per-neighbor outbound prefix maximum set for one unicast family no
  longer drops the other family's peer-group maximum. Each family now
  resolves on its own: a neighbor with only `max_prefixes_out_ipv4_unicast`
  keeps its group's `max_prefixes_out_ipv6_unicast`, as the commit-confirm
  rollback check already assumed.
  **Operator-visible:** such a neighbor's IPv6 (or IPv4) family is now
  capped by its group instead of unlimited, and a reload that would lower
  that cap below current usage is refused
  ([ADR-0113](../docs/adr/0113-outbound-prefix-limits.md)).
