### Changed

- The [v1 FlowSpec controller inventory](../docs/reference/v1-stable-contract.md#flowspec-controller-boundary)
  now pins `FlowSpecAction.traffic_rate_packets` and
  `FlowSpecTrafficRatePackets`, both on `AddFlowSpec` input and on the typed
  `ListFlowSpecRoutes` read-back. This pins the API shape only and adds no
  forwarding or enforcement guarantee; action communities are still echoed
  raw in `extended_communities`. The `0.ASN:value` read-back of a 4-octet-AS
  redirect whose ASN fits in 16 bits is now documented as RFC 5396 asdot+,
  the spelling that keeps the 4-octet encoding through a read and re-inject.
