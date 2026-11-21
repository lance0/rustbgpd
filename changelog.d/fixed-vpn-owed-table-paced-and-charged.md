### Fixed

- A receiver that is owed a whole VPNv4 or VPNv6 family is no longer sent
  it as one table-sized operation outside its outbound credit. That
  happened after an RFC 4724 selection release, and when the VPN routes a
  receiver was owed exceeded a quarter of its table. VPN now uses the row
  cursor unicast, labeled unicast and EVPN use: one shared list per
  address family of the route distinguisher and prefix keys that changed
  while any receiver owed the family, and at most 1,024 keys per step
  toward each receiver, each step an ordinary update charged against that
  receiver's credit, with the End-of-RIB after the last step. A selection
  release records its whole inventory in that list once, so a receiver
  that joined during the hold also gets the routes whose best path did not
  change, and a policy dataset re-evaluation records the keys it
  re-evaluates.
  **Operator-visible:** such a receiver gets its VPN table as many small
  updates over the resync ticks that follow; one that has stopped reading
  is queued at most its credit plus one step;
  `bgp_rib_outbound_operations_live` no longer counts these sends, and
  `bgp_rib_outbound_owed_drain_step_seconds` records them under scope
  `cursor` instead of `whole`. A receiver negotiated to be sent every
  Add-Path path of a key is sent one key per step. A receiver that falls
  behind while new routes keep replacing old ones is resynced instead, by
  the resync tick alone, and counted in
  `bgp_rib_outbound_owing_fallback_total`, as for unicast. VPN owned by an
  update group and a receiver whose RT-Constrain membership changes are
  unchanged. FlowSpec, BGP-LS and RT-Constrain keep the whole-family send;
  see [known issues](../docs/reference/known-issues.md).
