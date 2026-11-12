### Documentation

- The [guarded FlowSpec reference](../docs/reference/api.md#guarded-flowspec-mutations)
  states that a guarded rule accepts the same component grammar, actions,
  communities and VPN scope as `AddFlowSpec`, including rules without a
  destination component, and that export policy matches such a rule by its
  communities rather than a prefix term. A qualification test covers a
  destination-less guarded rule through admission, renewal, exact read-back,
  per-peer export by community and a revision-fenced delete.
