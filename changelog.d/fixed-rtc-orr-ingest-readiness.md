### Fixed

- The RIB now answers readiness probes while it applies an RT-Constrain
  UPDATE that changes a VPN update-group member's membership, and while it
  rebuilds the optimal-route-reflection cache for a BGP-LS UPDATE or for a
  peer binding or releasing an ORR vantage. Each of these ran as one actor
  turn that scaled with the group's VPN routes times the membership size, or
  with the topology size times the number of vantages, and could outlast the
  readiness deadline. A member that cannot be sent EVPN no longer has the
  EVPN table walked on its membership change.
  **Operator-visible:** BGP-LS UPDATEs already queued back to back rebuild the
  ORR topology once, when the last one is applied, and a re-announcement
  identical to the stored BGP-LS route rebuilds nothing, so
  `bgp_orr_spf_runs_total` grows more slowly during a BGP-LS burst. Route
  selection and BGP-LS advertisement are unchanged; ORR-bound peers receive
  the burst's net change instead of one update per intermediate topology.
