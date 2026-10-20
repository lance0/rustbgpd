### Added

- `rbgp rib delete` and `rbgp flowspec delete` take `--owner <name>` and
  `--override-owner` for entries added under an injection lease, so an
  operator can remove a stuck blackhole or filter whose controller is gone.
  Without them, deleting an owned entry fails with exit status 1, names the
  owner and points at both flags. `rbgp rib` route tables gain a `Lease`
  column, and `rbgp flowspec received 0.0.0.0` lines a `lease` suffix, when
  an entry is owned; `--json` rows gain a `lease` object (`owner`,
  `generation`, `remaining_ms`). Output for unowned entries is unchanged.
