### Added

- `rbgp diff snapshot from-mrt` spells its ASN flag `--neighbor-asn`, as
  `rpki verify-path` does; `--peer-asn` remains a visible alias.
  `rpki verify-path --role` accepts the config's role spellings:
  `route_server_client` and `route-server-client` for the RS-client role,
  and `rs` for the route-server role.
