### Added

- Conditional advertisement conditions accept prefix ranges (alpha, outside
  the v1 inventory). A `condition_prefixes` entry may be a table such as
  `{ prefix = "10.0.0.0/8", le = 24 }` or
  `{ prefix = "2001:db8::/32", ge = 48, le = 64 }`, with prefix-list `ge`/`le`
  semantics, beside the existing exact strings. Invalid bounds are load
  errors. Ranges are tracked as routes change, without a table walk.
  `rbgp policy conditional-advertisements` and
  `PolicyService.ListConditionalAdvertisements` report each range's bounds,
  its count of present prefixes, and up to eight of them. See
  [configuration](../docs/reference/configuration.md#conditional-advertisements).
