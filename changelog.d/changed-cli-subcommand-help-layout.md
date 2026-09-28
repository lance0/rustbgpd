### Changed

- `rbgp` subcommand help lists the command's own options first and the
  connection and output flags afterwards under one "Global options" heading,
  instead of interleaving the two. `--json-lines`, `--pager` and
  `--json-version` no longer appear in the help of commands that reject
  them; they still parse in every position, and the checks that reject them
  are unchanged. Arguments that had no help text now describe themselves
  (`evpn add-*`, `delete-*` and `explain *` key flags, `rpki aspa`,
  `peer-group` and `neighbor-set` names and `--from-file`), help names no
  internal design records, service names or status codes, and the `config`
  and `evpn` summaries describe what those commands do. `rbgp config
  history` points to `rbgp config rollback N` without naming the RPC. Help
  text is outside the v1 CLI contract; command paths, flags and exit codes
  are unchanged.
