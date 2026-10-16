### Added

- `.rpol` in-language tests can assert what a policy removes and what it
  leaves alone: `with removes community LIT` (and the `large-community` /
  `ext-community` forms), `without community LIT`, and `without
  local-pref|med|next-hop|prepend`. Previously a scrub term was covered only
  by `expect p == accept`, which still passed after the scrub was deleted.
  `expect chain [p1, p2(args), ...]` evaluates several policies as one
  configured chain, through the daemon's own chain assembly and merge rules,
  with coverage attributed to each member. The renderer's shared hygiene
  policy now includes a test that fails if any scrub term is removed. See
  [Tests](../docs/reference/rpol-language.md#tests).
