### Upgrade notes

- Scripts that call `rbgp` need these replacements:
  `rbgp events … -l N` → `--limit N`;
  `rbgp events … --limit 0` → `--all`;
  `rbgp policy test … --limit 0` → `--all` (or omit `--limit`);
  `rbgp policy stats` without `--direction` → `--direction export` for the
  previous answer (`import` and `both` are unchanged);
  `rbgp policy explain` without `--direction` → `--direction import` for the
  previous answer;
  `rbgp evpn received|advertised --page-size N` and
  `rbgp rib fib --page-size N` → `--limit N`, and `rib fib --page-size 0` →
  omit `--limit` for the full snapshot. An omitted `--direction` or a
  `--limit 0` now exits 2 with a usage error.
