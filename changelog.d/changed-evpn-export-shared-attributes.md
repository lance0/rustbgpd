### Changed

- EVPN routes whose attributes an export policy modifies now share one stored
  attribute set across every receiver and route with the same result, instead
  of keeping a separate copy per receiver and route. With many receivers on a
  community-tagging export policy, Adj-RIB-Out memory drops accordingly; other
  address families are unchanged.
