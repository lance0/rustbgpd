### Upgrade notes

- **`.rpol` guards no longer deny a route through an evaluation error.** In
  v0.81.0 a condition whose operand was missing (`route.origin-as` on an
  empty or `AS_SET`-only path, an unknown `peer.asn`), or whose arithmetic
  overflowed or underflowed, denied the route with an evaluation error. Now a
  missing operand makes the condition false, and `+ - *` saturate at 0 and
  4294967295, so the guard evaluates:
  - on MED 4, `route.med - 100 <= 5` used to deny with `underflow`; it now
    matches, as it does for every MED below 100;
  - on MED 4294967295, `route.med + 50 <= 1000` used to deny with
    `overflow`; it is now false, and the route falls through to the next
    term;
  - on an origin-less route, `route.origin-as + 0 == 64500` used to deny
    with `absent-operand`; it is now false.

  Review guards that compare a computed expression. Compare the field itself
  where a floor at zero is not wanted (`route.med <= 105`), and where a route
  without the value must still be rejected, add a presence test:
  `if !exists route.origin-as { reject }`.
- **`let` bindings and actions.** A `let` that cannot be computed no longer
  denies the route unless an action uses it. An action that needs a missing
  value (`set med route.origin-as`, a computed prepend operand, a community
  binding) still denies the route. A `set` or `let` that used to fail on
  overflow or underflow now applies the saturated value, so a route it used
  to deny is accepted with MED or local-pref 0 or 4294967295. Where a peer
  must not see 4294967295, which RFC 4451 notes some implementations treat as
  "infinity", cap it: `set med min(route.med + 50, 4294967294)`.
- **Conditional advertisement.** A guard that used to fail in a
  `condition_policy` now makes the candidate a miss instead of `unknown`, so
  the condition can change state rather than hold it; in an
  `advertise_policy` it is a clean reject instead of a fail-closed
  suppression.
- **Division needs a divisor that cannot be zero.** `route.med / x` with a
  field, binding or parameter divisor no longer loads; write
  `route.med / max(x, 1)`.
- **In-language tests that expect these errors now fail.**
  `expect p == error underflow`, `error overflow`, `error divide-by-zero`,
  `error remainder-by-zero` and `error clamp-inverted`, and
  `error absent-operand` from a guard, no longer match, because the policy
  now returns a verdict. `rustbgpd --check` reports the failure, and with
  `require_passing_tests = true` the config load is refused: the daemon does
  not start, and a SIGHUP reload is rejected and keeps the running policy,
  until the test is updated.
- **`optional-field-negation` flags more forms.** A negated binding, binding
  probe or computed comparison over `route.origin-as` or `peer.asn` is now
  flagged with a new message, so `rbgp policy check --deny-lints
  optional-field-negation` can fail on a policy that passed before.
