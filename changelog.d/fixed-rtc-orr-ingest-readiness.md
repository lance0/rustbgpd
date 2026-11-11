### Fixed

- The RIB now answers readiness probes while it applies an RT-Constrain
  UPDATE that changes a VPN update-group member's membership, and while it
  rebuilds the optimal-route-reflection cache for a BGP-LS UPDATE or for a
  peer binding or releasing an ORR vantage. Each of these ran as one actor
  turn that scaled with the group's VPN routes times the membership size, or
  with the topology size times the number of vantages, and could outlast the
  readiness deadline. A member that cannot be sent EVPN no longer has the
  EVPN table walked on its membership change.
  **Operator-visible:** BGP-LS UPDATEs already queued back to back, up to 32
  at a time, rebuild the ORR topology once, when the last one is applied, and
  a re-announcement identical to the stored BGP-LS route rebuilds nothing.
  Route selection and BGP-LS advertisement are unchanged; ORR-bound peers
  receive the burst's net change instead of one update per intermediate
  topology. During such a burst `bgp_orr_spf_runs_total` grows more slowly,
  and the ORR topology gauges (nodes, links, unresolved vantages, input
  diagnostics) and the input-diagnostics log line show the topology as of
  the last rebuild until the burst ends; an operator query rebuilds first
  and so always reads the current topology. A vantage that stops resolving
  and resolves again within one burst is no longer logged.
