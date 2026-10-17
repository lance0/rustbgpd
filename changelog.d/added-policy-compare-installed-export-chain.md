### Added

- `rbgp policy compare` and the `ComparePolicy` RPC compare a candidate
  `.rpol` export chain with the chain installed for one peer over the same
  live Loc-RIB walk, and report only the routes that change: newly
  rejected, newly accepted, and accepted with different attributes, with
  exact counts and at most 1,000 samples per class. `--replace MEMBER`
  swaps one installed member and keeps the rest of the chain, so routes an
  earlier member rejects are not reported as candidate accepts. Native
  egress steps apply to neither side. The run is read-only, moves no
  counters, requires `SensitiveRead`, and is outside the v1 inventory
  ([comparing with the installed chain](../docs/reference/rpol-language.md#comparing-a-candidate-with-the-installed-export-chain)).
