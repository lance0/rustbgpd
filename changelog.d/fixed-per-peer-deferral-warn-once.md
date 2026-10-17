### Fixed

- A peer outside an update group whose outbound channel stays full now
  logs `outbound channel full — <family> update deferred` (VPN, EVPN,
  labeled, FlowSpec, BGP-LS or RTC) once, when it first falls behind,
  instead of once per distribution pass for every family with a change.
  The message text and fields are unchanged. The existing
  `outbound routes resynced` info event still marks recovery, and
  `bgp_outbound_route_drops_total` still counts every refused send.
  **Operator-visible:** a slow or paused receiver no longer floods the
  log with these warnings; `bgp_rib_outbound_dirty_peers` and
  `bgp_rib_outbound_dirty_oldest_seconds` show how long it stays behind.
