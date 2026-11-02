### Upgrade notes

- **`.rpol` guards that relied on an evaluation error now fall through.** A
  condition whose operand is missing or cannot be computed was an evaluation
  error that denied the route; it is now false. Review guards that compare a
  computed expression over `route.origin-as` or `peer.asn` (arithmetic, a
  parenthesized value, or a `let` binding), or divide by a value that can be
  zero. Where such a route must still be rejected, add a presence test:
  `if !exists route.origin-as { reject }`. Tests that pinned the old behavior
  with `expect … == error absent-operand` on a guard now see the policy's
  verdict instead. A `let` that cannot be computed no longer denies the route
  unless an action uses it. Actions are unchanged: a computed `set` value, a
  computed prepend operand or a community binding that cannot be computed
  still denies the route. For conditional advertisement, such a guard in a
  `condition_policy` now makes the candidate a miss instead of `unknown`, so
  the condition can change state rather than hold it; in an
  `advertise_policy` it is a clean reject instead of a fail-closed
  suppression.
