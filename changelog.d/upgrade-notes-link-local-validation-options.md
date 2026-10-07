### Upgrade notes

- The prepared embedding crate set is wire 0.24, FSM 0.11, and RPKI 0.6.
  `UpdateValidationOptions` is now `#[non_exhaustive]` and gains
  `link_local_next_hop`: replace struct literals with
  `UpdateValidationOptions::default()` plus field assignment. The default
  retains strict validation.
  Upgrade crates sharing wire types together. Published dependency examples
  remain on the previous release set until coordinated publication.
- Daemon operators: a route whose outbound next hop is IPv6 link-local is now
  advertised only to peers on the interface where it was learned, whether or
  not capability 77 is configured. Routes that previously crossed interfaces, such
  as IPv4 reflected between unnumbered peers or a policy `set next-hop` to a
  link-local address, are withheld and withdrawn; set next-hop self or
  `local_ipv6_nexthop` where they must still reach those peers. Watch
  `bgp_exact_export_rejections_total{reason="missing_ipv6_next_hop"}` after
  upgrading. Capability 77 itself stays off unless `link_local_next_hop` is set.
