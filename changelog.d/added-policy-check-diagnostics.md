### Added

- `rbgp policy check` reports compiler-stage finding codes (`lex-error`,
  `parse-error`, `resolve-error`, `typecheck-error`, `lower-error`) and the
  gateable `optional-field-negation` lint for negated equalities that match
  an absent optional field. JSON keys, format version and exit precedence
  are unchanged; consumers selecting all compile errors should use finding
  severity rather than the older generic `compile-error` value.
