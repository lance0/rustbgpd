### Fixed

- FlowSpec `ListFlowSpecRoutes` now reports the IPv4-address and 4-octet-AS
  redirect forms (RFC 7674) and traffic-rate-packets as typed `actions`;
  previously they appeared only as raw `extended_communities`. `AddFlowSpec`
  accepts all three redirect forms in `FlowSpecRedirect.route_target`
  (`ASN:value`, `a.b.c.d:value`, or RFC 5396 asdot `high.low:value`), where it
  accepted only the 2-octet-AS form, and the new
  `FlowSpecAction.traffic_rate_packets` variant, outside the v1 inventory.
  `rbgp flowspec` shows and accepts it as `rate-pps=N`, and now shows both
  rates exactly: a fractional rate such as `rate=0.25` was displayed
  rounded, as `rate=0`, which reads as discard. Action communities
  are still echoed raw in `extended_communities`; see the
  [API reference](../docs/reference/api.md#list-flowspec-routes).
  **Operator-visible:** a 4-octet-AS redirect whose ASN fits in 16 bits reads
  back as `0.ASN:value`, and `ASN:value` with an ASN above 65535, previously
  rejected, now selects the 4-octet-AS form.
