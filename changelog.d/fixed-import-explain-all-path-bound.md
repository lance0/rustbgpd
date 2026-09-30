### Fixed

- Bound import-policy explain queries without a path ID to 4096 matches.
  Larger queries fail with a path-ID hint instead of building an oversized
  response; exact path-ID lookups still work.
