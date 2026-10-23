### Added

- The RIB publishes `bgp_rib_outbound_registration_pending_peers`, the number
  of Established sessions that have a live-session record but no outbound
  registration, and `bgp_rib_outbound_registration_pending_oldest_seconds`,
  the age of the oldest such wait measured from its `PeerUp`. The count comes
  from the session records rather than the deferral queue, so a registration
  lost inside the RIB stays visible and keeps ageing.
  **Operator-visible:** `rbgp doctor`'s `peer.<addr>.outbound` advisory
  reports the RIB's count and oldest wait instead of an unknown duration when
  its metrics scrape includes them; it remains a warning. The route-server,
  route-reflector and EVPN route-reflector soak analyzers record the maximum
  sampled age and fail a run above 300 seconds. Readiness does not use the age. See
  [delayed outbound registration](../docs/reference/operations.md#delayed-outbound-registration).
