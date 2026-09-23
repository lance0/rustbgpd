### Documentation

- The `rbgp policy test` reference and `--help` text and the `TestPolicy`
  API reference now state that an import dry run evaluates the retained
  post-policy Adj-RIB-In: routes admitted by import policy when they were
  received or last re-evaluated. Under an active GR/LLGR window, or before a
  Route Refresh replay re-evaluates routes after an import-policy change, it
  can hold routes the installed chain would now reject. The dry run does not
  show routes a candidate would newly admit;
  `rbgp rib received PEER --rejected` lists recent rejections within the
  `[policy.reject_retention]` bound. See the
  [`.rpol` reference](../docs/reference/rpol-language.md#live-rib-policy-dry-runs).
