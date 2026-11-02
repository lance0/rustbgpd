### Changed

- **Breaking:** `.rpol` community actions apply in statement order, within a
  term, across terms and across chain members, and the later operation on a
  value wins: `add community X; remove community X` now leaves X absent, where
  both orders used to keep it. `remove community *`, the other strip-all forms,
  `remove large-community <asn>:*:*` and `remove <kind> in / not in` now also
  cancel matching additions that earlier statements or chain members staged,
  where they used to read only the arrived route; `remove community *` still
  keeps well-known communities, even ones the policy just added. Conditions
  still read the route as received. See
  [Actions](../docs/reference/rpol-language.md#actions).
