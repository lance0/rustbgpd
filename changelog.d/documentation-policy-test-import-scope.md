### Documentation

- The `rbgp policy test` reference and `--help` text and the `TestPolicy`
  API reference now state that an import dry run evaluates only the
  post-policy Adj-RIB-In: routes the current import policy accepted. The dry
  run shows which accepted routes a candidate would reject or modify, but not
  which routes it would newly admit; `rbgp rib received PEER --rejected` lists
  recent rejections within the `[policy.reject_retention]` bound. See the
  [`.rpol` reference](../docs/reference/rpol-language.md#live-rib-policy-dry-runs).
