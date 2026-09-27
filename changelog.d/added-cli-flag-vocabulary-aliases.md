### Added

- `rbgp` flag spellings now carry from one command to the next. `events` and
  its `watch`, `sessions`, `policy` and `evpn` subcommands select a peer with
  `--neighbor` (visible alias `--peer`; the old `--address` still parses), and
  `diff snapshot from-mrt|from-bmp` take `--neighbor` alongside `--peer`.
  `evpn add-imet` and `delete-imet` accept `--originator-ip`, the name
  `evpn explain imet` uses, alongside `--ip`. `rib add --origin` accepts
  `igp`, `egp` and `incomplete`, the names every output prints, as well as
  the numeric codes. Multi-word values accept either separator where the
  CLI knows them: `--rpki-state not-found`, `rpki verify-path --role
  rs_client`, `diff snapshot from-mrt --view adj_rib_out_capture`,
  `diff advertised --ignore-attribute as-path`, and kebab-case event
  `--type` names. Canonical spellings and all output are unchanged.
