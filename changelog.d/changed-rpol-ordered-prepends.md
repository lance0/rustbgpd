### Changed

- **Breaking:** `.rpol` prepends accumulate in statement order, across terms
  and chain members, each later prepend to the left of the earlier ones, as
  IOS-XR RPL `prepend as-path` does: `prepend as 131077 3` then
  `prepend as 43646981 2` places `666.5 666.5 2.5 2.5 2.5` in front of the
  path. A later prepend used to replace an earlier one. TOML
  `set_as_path_prepend` statements in different chain members accumulate the
  same way. One evaluation prepends at most 255 ASNs: the compiler sums every
  prepend, each `if` branch included, times its enclosing loop bounds, and
  rejects a policy, or a chain when it is attached, that could exceed that,
  so a prepend inside a loop over a route attribute is a compile error; a
  chain composed without the check fails the route closed with the new
  `prepend-limit-exceeded` evaluation error. The in-language test assertion
  `with prepend "666.5 666.5 2.5 2.5 2.5"` pins the whole prepended
  sequence, leftmost first, in asplain or asdot, and `with prepend as ASN
  COUNT` now also pins the whole sequence. See
  [Actions](../docs/reference/rpol-language.md#actions).
- **Breaking:** `ExplainModifications.as_path_prepend` (field 12, repeated)
  carries the prepended ASNs, leftmost first, in `ExplainImportPolicy`,
  `ExplainAdvertisedRoute` and `TestPolicy` responses. It replaces
  `as_path_prepend_asn` and `as_path_prepend_count`, whose field numbers and
  names are reserved. The `rbgp` JSON output's `as_path_prepend` is the same
  array, replacing the two keys, and the text output prints the sequence.
