### Changed

- Include EVPN Types 1–5 route reflection in the narrow v1 compatibility
  inventory as the scoped RR-only `route-reflector-evpn` role. It covers the
  `l2vpn_evpn` family value in the existing family keys;
  `ListReceivedEvpnRoutes` and `ListAdvertisedEvpnRoutes` called with a route
  type of 1 to 5, with `EvpnRouteEntry` fields 1–16; the `rbgp evpn received`
  and `rbgp evpn advertised` command paths with `--route-type` 1 to 5 and the
  key/type floor of their `--json` page; and the names, types and labels of
  nine RIB, loop, discard and restart metrics. The unpaged `ListEvpnRoutes`
  query and base `rbgp evpn` command, `ExplainEvpnRoute`, EVPN events,
  unfiltered or Type 6 peer-view calls, `EvpnRouteEntry.prefix_sid` and
  `.smet`, Type 6 SMET relay, VTEP, IRB, multi-homing, local EVI and segment
  configuration, and every Linux dataplane behavior remain alpha. See the
  [EVPN reflector boundary](../docs/reference/v1-stable-contract.md#evpn-route-reflector-boundary).
