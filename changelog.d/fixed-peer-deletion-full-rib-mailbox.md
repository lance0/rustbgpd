### Fixed

- Deleting a neighbor no longer stops the peer manager while the RIB mailbox
  is full. Operator deletes, reconcile, dynamic-neighbor auto-removal and
  retained-identity expiry used to wait for mailbox room before handling
  anything else, so a RIB that stopped draining also stopped inbound accepts,
  session notifications and neighbor commands while readiness stayed green.
  The deletion's RIB cleanup now waits in order behind the full mailbox while
  the peer manager keeps working, including the removal of an interface-only
  neighbor. Every later RIB update sent through the peer manager's ordered
  path still goes after that cleanup. Re-adding the deleted neighbor waits
  until its cleanup is admitted, so a static re-add still waits for mailbox
  room. An interface-only neighbor's binding never waits: a binding learned
  from Router Advertisements is retried on the reconcile timer until the
  cleanup ahead of it is admitted.
  **Operator-visible:** while any cleanup waits, inbound connections that
  would create a new RIB identity are refused: a new dynamic neighbor (also
  when it evicted a dynamic neighbor kept for graceful restart), or a
  collision candidate beside one. A connection that would start a session
  under a deleted neighbor's `peer` label is refused until that neighbor's
  cleanup is admitted. A connection that would bind an interface-only
  neighbor is refused under that label, and under any cleanup while the
  neighbor keeps its RIB identity across addresses. A dynamic
  neighbor kept for graceful restart can still reconnect. Refusals are
  counted as `bgp_inbound_connections_dropped_total{reason="rib_cleanup_pending"}`,
  a new series exported at 0 from startup, and the neighbor reconnects on its
  own timer.
