### Added

- `.rpol` can express the NLNOG "many communities" filter practice.
  `route.communities.len`, `route.large-communities.len` and
  `route.ext-communities.len` are u32 fields usable in comparisons and
  arithmetic, and `remove community *`, `remove large-community *:*:*` and
  `remove ext-community *` remove every arrived value of that kind. The
  counts read only the route, so they never disqualify update-group
  sharing; a strip-all fails the route closed above the attribute's wire
  bound, like `remove large-community GA:*:*`. In-language tests can pin
  the result with `removes community *` and the other two forms. See
  [the language reference](../docs/reference/rpol-language.md#routes-that-carry-too-many-communities)
  for the summed (BIRD) and per-kind (OpenBGPD) shapes.
