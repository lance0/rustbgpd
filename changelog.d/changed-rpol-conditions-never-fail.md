### Changed

- `.rpol` conditions never fail. A comparison or probe whose operand is
  missing or cannot be computed is false, so `&&`, `||` and `!` combine plain
  true and false values and an operand's evaluation order never changes a
  verdict. Before, `if route.as-path matches "^65000" && route.origin-as + 0
  == 1 { reject }` denied an `AS_SET`-only route with `absent-operand` even
  though the regex was false, and `route.origin-as == (64500)` denied where
  `route.origin-as == 64500` did not match. A `let` that cannot be computed
  now binds that state: conditions on it are false, and only an action that
  needs the value denies the route. Computed `set` values, computed prepend
  operands and community bindings still fail closed. See
  [Conditions never fail](../docs/reference/rpol-language.md#conditions-never-fail).
