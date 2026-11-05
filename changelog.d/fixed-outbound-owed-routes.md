### Fixed

- A receiver whose outbound row credit is spent no longer falls back to a
  whole-peer resync for the families it holds in its own Adj-RIB-Out
  (ungrouped unicast, labeled unicast, private VPN and EVPN). The RIB records
  which routes it owes, keeps one entry per route however often the route
  changes, and drains older owed keys first from current state once the
  receiver drains, checking returned credit every 10 ms. A full outbound
  channel retains the debt without repeatedly staging it. Local host and
  BLACKHOLE route withdrawals and local FlowSpec revocations continue to
  drain during graceful-restart selection deferral. A route-reflector client
  with grouped unicast and private EVPN therefore keeps its grouped unicast
  on the shared path while its EVPN backs up. End-of-RIB, route-refresh markers and an
  operator replay's terminal are sent only after the routes the receiver was
  owed in their family, including after a failed absorption falls back to
  resync. Owed-set capacity is capped using a quarter-table byte estimate
  with a 64-key floor; above it, the family is sent by one diff instead.
  Queue and membership-map allocations shrink independently as keys drain.
  FlowSpec, BGP-LS and RT-Constrain always take that path. Global and VPN
  FlowSpec keep separate debt and refresh ordering. Shutdown makes a
  best-effort flush of owed withdrawals ahead of the Cease. A graceful-restart
  helper's carried withdrawals are sent in chunks admitted one at a time
  against the receiver's credit.
  **Operator-visible:** a new `owing` outcome on
  `bgp_rib_dirty_resync_total`, and new counters
  `bgp_rib_outbound_owing_flips_total` and
  `bgp_rib_outbound_owing_fallback_total`.
