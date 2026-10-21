### Added

- The gRPC API reports the interface of an IPv6 link-local neighbor beside
  its bare `peer_address`: `peer_interface` on `Route`, `RouteSourceIdentity`,
  `PathExportDispositionEntry`, `OrrExplainCandidate`,
  `ExplainBestPathResponse`, `ExplainImportPolicyResponse`,
  `ImportExplainMatch`, `ListRejectedRoutesResponse`, `SessionEvent`,
  `NotificationEvent` and `PolicyEvent`; `peer_interface`,
  `previous_peer_interface` and `target_peer_interface` on `RouteEvent`; and
  `peer_interface` plus `route_peer_interface` on
  `ExplainAdvertisedRouteResponse`. The address and interface together
  identify the neighbor; the interface is empty for numbered neighbors. Route
  rows and route events report the interface recorded when the route was
  learned or the event was recorded, so retained routes and the history of a
  deleted neighbor keep it. See
  [scoped neighbor identity](../docs/reference/api.md#scoped-neighbor-identity).
