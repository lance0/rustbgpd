### Added

- `rbgp rib add` prints the unicast injection outcome, for example
  `Route 10.99.0.0/24 added (unchanged)`, and `rbgp rib delete` takes
  `--allow-missing`, which exits 0 and prints `Route 10.99.0.0/24 not present`
  for an absent route; without the flag a missing route is still an error.
  The `--json` results of both carry `outcome` (`created`, `replaced`,
  `unchanged`, `deleted`, `not_present`, or `unknown` for an older daemon), as
  `rbgp flowspec add` and `delete` already do. The
  [API reference](../docs/reference/api.md#unicast-injection-contract)
  describes the outcomes.
