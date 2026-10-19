### Changed

- The unicast max-prefix bounds now use the canonical family label like
  every other family bound: `max_prefixes_ipv4_unicast`,
  `max_prefixes_ipv6_unicast`, `max_prefixes_received_ipv4_unicast`,
  `max_prefixes_received_ipv6_unicast`, `max_prefixes_out_ipv4_unicast` and
  `max_prefixes_out_ipv6_unicast`. `rs-config-render`, the CLI config
  importers, `rbgp config diff` output and configs the daemon writes back use
  the new names, and the render receipt reports per-client limits under them.
- Every config key that `rs-config-render` writes is now in the
  [v1 stable surface](../docs/reference/v1-stable-contract.md): the four
  unicast accepted and pre-policy bounds above, `max_prefix_action`,
  `max_prefix_restart_seconds`, `next_hop_ownership`,
  `rs_control_communities` and `interpret_rfc1997` on neighbors and peer
  groups, and `honor_blackhole` and `listen_addresses` under `[global]`.
  `listen_addresses` was alpha. The `max_prefixes` reference now states that
  a crossed aggregate bound applies `max_prefix_action`, so under `"warning"`
  it logs instead of tearing the session down.
