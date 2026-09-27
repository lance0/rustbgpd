### Changed

- `rbgp` flags now mean one thing across commands. `-l` is only `--longer`:
  `events` and its `sessions`, `policy` and `evpn` subcommands drop it as a
  short form of `--limit`. `policy stats` and `policy explain` require
  `--direction` instead of defaulting to opposite directions. Paged reads use
  `--limit N` with `--page-token`: `evpn received|advertised` and `rib fib`
  rename `--page-size` to `--limit` (the old spelling still parses), and
  `--limit 0` is a usage error everywhere, with a new `--all` flag on `events`
  and `policy test` for the full window. `rbgp rib`, `rib received` and
  `rib advertised` accept `--page-token` with `--limit` and print the next
  token: `Next page token: …` in human output and an additive
  `next_page_token` field in the `--json --limit` envelope. Omitting a flag
  keeps its previous behaviour.
