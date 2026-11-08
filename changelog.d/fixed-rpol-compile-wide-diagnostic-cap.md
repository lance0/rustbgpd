### Fixed

- An rpol compile now keeps at most 256 diagnostics across lexing, parsing,
  import resolution and typechecking together. The 256-diagnostic limit
  added in 0.82.0 covered typechecking only, so a 4 MiB source of lex or
  parse errors still built every diagnostic: 4 MiB of `@a` lines produced
  about 1.4 million diagnostics and about 400 MB of memory. Lexing and
  parsing now stop at the cap, and the rendered output's closing line says
  so: `... N more diagnostic(s) not shown; a compile keeps at most 256`.
  This applies to `TestPolicy`, `ComparePolicy`, `rbgp policy check` and
  config load errors.
