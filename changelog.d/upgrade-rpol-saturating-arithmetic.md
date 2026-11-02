### Upgrade notes

- **`.rpol` subtraction inside a guard now matches small values.** With
  saturation, `route.med - 100 <= 5` is true for every MED below 100, where
  it used to be false. Review guards that subtract from a field and compare
  the result; compare the field itself instead (`route.med <= 105`). A `set`
  or `let` that used to fail on overflow or underflow now applies the
  saturated value, so a route it used to deny is accepted with MED or
  local-pref 0 or 4294967295. Where a peer must not see 4294967295, which
  RFC 4451 notes some implementations treat as "infinity", cap it:
  `set med min(route.med + 50, 4294967294)`.
- **Division needs a divisor that cannot be zero.** `route.med / x` with a
  field, binding or parameter divisor no longer loads; write
  `route.med / max(x, 1)`.
- **In-language tests that expected an arithmetic error now fail.**
  `expect p == error overflow`, `error underflow`, `error divide-by-zero`,
  `error remainder-by-zero` and `error clamp-inverted` no longer match, because
  evaluation no longer produces those errors. With
  `require_passing_tests = true`, such a test refuses the config load: the
  daemon does not start, and a SIGHUP reload is rejected and keeps the
  running policy, until the test is updated.
