### Changed

- Output now uses one spelling per value, the one configuration uses. The
  gRPC `NeighborConfig.role`, `NeighborState.local_role` and
  `NeighborState.remote_role` report `route_server` and `route_server_client`
  instead of `rs` and `rs-client`, so `rbgp neighbor` shows the same names
  as config, events and the `bgp_role_mismatch_total` labels. An absent Role
  stays an empty string on the API and `none` in that metric. The neighbor
  detail's distribution mode is `single_best`, `add_path` or
  `per_client_best` instead of the kebab-case forms.
  `rbgp rpki verify-path --role` lists `route_server` and
  `route_server_client`. The old spellings stay accepted as input aliases in
  configuration, the gRPC role field and the CLI.
- `rbgp` parser and usage errors (an unknown flag or subcommand, or a missing
  or malformed argument) exit `64` (`EX_USAGE`) instead of `2`, so they no
  longer collide with `2` meaning "changes present" for `config diff` and
  `config plan` or "red checks found" for `doctor`. `--help` and `--version`
  still exit `0`. The [v1 inventory](../docs/reference/v1-stable-contract.md)
  now pins the exit codes of `config diff`, `config plan`, `config apply`,
  `config confirm`, `config abort` and `doctor`.
