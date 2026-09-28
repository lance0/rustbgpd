### Fixed

- `rbgp policy check` and `rbgp policy fmt` diagnostics now follow the CLI
  colour policy. `--no-color`, `NO_COLOR` and `TERM=dumb` remove the ANSI
  colour codes they previously wrote to a terminal stderr; a colour-capable
  terminal still gets coloured diagnostics.
