### Added

- Prepare bounded recovery provenance and connection-fenced reset handling for
  EVPN update groups. The counter
  `bgp_evpn_recovery_provenance_exhausted_total{cause}` records resets accepted by
  the captured connection. EVPN grouping remains inactive pending storage,
  encoding and qualification; current private EVPN exports are unchanged.
