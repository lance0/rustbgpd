### Fixed

- `bgp_outbound_route_drops_total{peer}` now counts a full or closed peer
  writer channel for every address family. FlowSpec, EVPN, BGP-LS, VPN,
  labeled-unicast and RT-Constrain deferrals were previously only logged.
  The counter no longer counts fail-closed commit refusals, which are now
  counted in the new `bgp_outbound_commit_refusals_total{peer,reason}`, with
  `reason` set to `selection_gate`, `missing_encoder` or `evpn_recovery`.
  The warnings for unicast, initial-dump, route-refresh and RT-Constrain
  membership sends that were not delivered now carry a `reason` field and no
  longer report a refusal as a full channel.
  **Operator-visible:** `BgpOutboundRouteDrops` is now warning severity and
  describes the automatic dirty-peer resync instead of asking for a manual
  outbound refresh. The new critical `BgpOutboundResyncStalled` alert fires
  when the resync timer has not drained for 15 minutes; both
  `bgp_rib_dirty_resync_total` outcomes are now exported at 0 from startup so
  the first drain is visible to `increase()`. The new warning
  `BgpOutboundCommitRefused` alert fires on `missing_encoder` refusals. The
  Grafana "RIB ingest pressure" panel plots refusals by reason. See the
  [alert notes](../docs/how-to/grafana.md).
