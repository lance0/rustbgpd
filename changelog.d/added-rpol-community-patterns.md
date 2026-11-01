### Added

- `.rpol` community sets and community datasets accept patterns: a field
  may be `*`, an inclusive range `a..b`, or `PRIVATE_AS` (RFC 6996), as in
  `65000:*`, `*:666`, `65000:100..199`, `PRIVATE_AS:*`, `65000:1..9:*` and
  `RT:65000:*`, for standard, large and extended communities. Patterns
  match through `in`, including `<binding> in <set>`, and are rejected as
  `add`/`remove`/`has` values. Exact-only sets evaluate as before; a set
  whose patterns could cost more than 64 comparisons per route community
  is a load error. See
  [Community patterns](../docs/reference/rpol-language.md#community-patterns).
