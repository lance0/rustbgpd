### Upgrade notes

- FlowSpec controllers must retain desired state and re-inject it after a
  daemon restart. Check explicit mutation outcomes and received/advertised
  view acknowledgements, including empty responses, when upgrading or rolling
  back to an older daemon. Unknown outcomes and ignored selectors do not prove
  unchanged, absent or advertised state. The promotion changes no configuration
  defaults or wire behavior; see the
  [controller upgrade guidance](../docs/reference/v1-stable-contract.md#controller-upgrade-and-rollback).
