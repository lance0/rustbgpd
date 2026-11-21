### Fixed

- A receiver outside an update group that is owed a whole IPv4 or IPv6
  unicast table is no longer sent it as one table-sized operation outside
  its outbound credit. That happened after an RFC 4724 selection release,
  and when the routes a receiver was owed exceeded a quarter of its table;
  each such send was one RIB turn that grew with the table and held every
  peer's updates behind it. The RIB now keeps, per address family, one list
  of the routes that changed while any receiver owed the family, and sends
  each receiver the next routes after its position: at most 1,024 per
  step, each step an ordinary update charged against that receiver's
  credit. The family's End-of-RIB follows the last step.
  **Operator-visible:** such a receiver gets its table as many small
  updates over the resync ticks that follow; one that has stopped reading
  is queued at most its credit plus one step; and
  `bgp_rib_outbound_operations_live` no longer counts these sends. A
  receiver whose owed routes exceeded a quarter of its table keeps that
  set: it stays owed until every route in it is sent, and changes that
  arrive meanwhile go to the shared list. A
  receiver that falls behind while new routes keep replacing old ones (it
  has stopped reading, or reads more slowly than the table turns over),
  until it has more of the list still to read than twice the most routes
  one pass accounted for (the family's table after the pass plus the
  routes it carried) plus 4,096, is resynced instead and counted in
  `bgp_rib_outbound_owing_fallback_total`. That takes one to three tables'
  worth of prefixes the list has not held before; one large withdrawal, a
  peer loss or a selection release does not cause it. The resync is one
  whole-table operation per receiver, outside its credit and in one RIB
  turn that grows with the table. Only the resync tick runs it, one
  receiver per unit; no update pass does. Other receivers' steps still run
  on every tick meanwhile, for about 25 ms per resync. A full outbound
  channel at the last step delays only the End-of-RIB, which the resync
  tick retries; the table is not sent again. A ROUTE-REFRESH
  answer or an operator replay for a family still owed sends the remainder
  in its own operation, as before: the owed routes, the initial End-of-RIB
  that waited for them, then the answer between its BoRR and EoRR. A
  ROUTE-REFRESH from a receiver waiting for the resync above is answered
  after it, in the same order. FlowSpec, BGP-LS and RT-Constrain
  keep the whole-family send; see
  [known issues](../docs/reference/known-issues.md).
