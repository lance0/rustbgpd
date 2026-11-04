### Fixed

- A receiver whose outbound row credit is spent no longer falls back to a
  whole-peer resync for the families it holds in its own Adj-RIB-Out
  (ungrouped unicast, labeled unicast, private VPN and EVPN). The RIB records
  which routes it owes, keeps one entry per route however often the route
  changes, and sends each from current state once the receiver drains, within
  about 10 ms of credit returning. A route-reflector client with grouped
  unicast and private EVPN therefore keeps its grouped unicast on the shared
  path while its EVPN backs up. End-of-RIB, route-refresh markers and an
  operator replay's terminal are sent only after the routes the receiver was
  owed in their family. A receiver that owes more than a quarter of a
  family's table is sent that family by one diff instead; FlowSpec, BGP-LS
  and RT-Constrain always take that path. At shutdown, owed withdrawals go
  out ahead of the Cease. A graceful-restart helper's carried withdrawals are
  sent in chunks admitted one at a time against the receiver's credit.
  **Operator-visible:** a new `owing` outcome on
  `bgp_rib_dirty_resync_total`, and new counters
  `bgp_rib_outbound_owing_flips_total` and
  `bgp_rib_outbound_owing_fallback_total`.
