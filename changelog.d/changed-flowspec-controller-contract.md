### Changed

- Include the IPv4/IPv6 FlowSpec controller role in the existing narrow v1
  compatibility inventory: `AddFlowSpec`, `DeleteFlowSpec`, and selected,
  retained local-intent and committed advertised `ListFlowSpecRoutes` modes.
  Receive-side validation, its shared diagnostic fields, remote received mode,
  `Config.flowspec`, FlowSpec CLI surfaces, GR/LLGR guarantees and dataplane
  enforcement remain outside the promise. The existing pre-v1 rules apply
  during 0.x; inventoried surfaces remain functional throughout 1.x after
  v1.0. See the [controller boundary](../docs/reference/v1-stable-contract.md#flowspec-controller-boundary).
