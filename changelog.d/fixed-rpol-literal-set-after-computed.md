### Fixed

- In an rpol term, a literal `set med` or `set local-pref` now replaces an
  earlier computed `set` of the same attribute, as the
  [language reference](../docs/reference/rpol-language.md) documents. The
  computed value previously won: `set med route.med + 5; set med 10` gave
  MED 105 on a route with MED 100. The same applied inside loop bodies and
  in an applied policy's terms; a computed `set` after a literal one, and
  `set`s in separate terms, were already correct.
  **Operator-visible:** policies with a literal `set` after a computed `set`
  of the same attribute in one term now advertise, and select on, the
  literal value. Accept and reject verdicts are unchanged. If a policy
  relied on the old result, check it with `rbgp policy check`, which runs
  its `test` blocks, before upgrading.
