### Fixed

- A neighbor's `flap_count` and `notifications_received` / `notifications_sent`
  (API `NeighborState`, `rbgp neighbor`, and the gNMI `established-transitions`
  leaf) no longer drop back to 0 when a reset session re-establishes on a new
  session, for example after the peer sends a Hard Reset and reconnects
  inbound. They now read the same daemon-lifetime counters as
  `bgp_session_flaps_total` and `bgp_notifications_{received,sent}_total`,
  and are cleared only by a daemon restart or by deleting the neighbor.
  **Operator-visible:** the Cease 6/7 sent to drop the losing side of a
  connection collision is now also counted in `bgp_notifications_sent_total`.
