### Fixed

- IPv4/IPv6-unicast Add-Path receive now caps each prefix at 1024 retained
  path IDs when `add_path.receive_max` is unset or zero. Before, such a peer
  could announce any number of path IDs for one prefix, and each insert and
  withdrawal in the RIB scanned that prefix's whole path list, so 100,000 IDs
  for one prefix cost about two seconds of RIB work. Past the default cap the
  excess is withheld as `max_prefix_action = "block"` does, independent of
  the configured action, and counted in
  `bgp_add_path_receive_limit_attempts_total` with `action="block"`. No
  Paths-Limit capability is advertised for the default. See
  [Add-Path configuration](../docs/reference/configuration.md).
