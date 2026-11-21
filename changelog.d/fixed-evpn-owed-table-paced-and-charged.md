### Fixed

- A receiver that holds EVPN outside an update group and is owed the whole
  family is no longer sent it as one table-sized operation outside its
  outbound credit. That happened after an RFC 4724 selection release, and
  when the EVPN routes a receiver was owed exceeded a quarter of its
  table. EVPN now uses the row cursor unicast uses: one shared list of the
  route keys that changed while any receiver owed the family, and at most
  1,024 routes per step toward each receiver, each step an ordinary update
  charged against that receiver's credit, with the End-of-RIB after the
  last step. A selection release records its whole inventory in that list
  once, so a receiver that joined during the hold also gets the routes
  whose best path did not change.
  **Operator-visible:** such a receiver gets its EVPN table as many small
  updates over the resync ticks that follow; one that has stopped reading
  is queued at most its credit plus one step;
  `bgp_rib_outbound_operations_live` no longer counts these sends, and
  `bgp_rib_outbound_owed_drain_step_seconds` records them under scope
  `cursor` instead of `whole`. A receiver that falls behind while new
  routes keep replacing old ones is resynced instead, by the resync tick
  alone, and counted in `bgp_rib_outbound_owing_fallback_total`, as for
  unicast. A live RT-Constrain membership change toward a receiver that is
  still being sent its EVPN table is applied to the routes already sent
  as well. EVPN owned by an update group is unchanged. FlowSpec,
  BGP-LS and RT-Constrain keep the whole-family send; see
  [known issues](../docs/reference/known-issues.md).
