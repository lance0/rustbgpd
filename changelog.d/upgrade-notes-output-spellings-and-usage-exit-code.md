### Upgrade notes

- Scripts that match BGP Role or distribution-mode output must use the
  configuration spellings: `route_server` and `route_server_client` rather
  than `rs` and `rs-client`, and `single_best`, `add_path` and
  `per_client_best` rather than their kebab-case forms. Inputs and metric
  labels are unaffected.
- `rbgp` now exits `64` on a parser or usage error. A script that treated
  exit `2` from `rbgp` as a usage error must check for `64`; a script that
  gates on `config diff`, `config plan` or `doctor` exiting `2` no longer
  mistakes a renamed flag or missing argument for changes or red checks.
