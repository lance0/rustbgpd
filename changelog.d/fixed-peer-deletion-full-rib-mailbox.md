### Fixed

- Deleting a neighbor no longer stops the peer manager while the RIB mailbox
  is full. Operator deletes, reconcile, dynamic-neighbor auto-removal and
  retained-identity expiry used to wait for mailbox room before handling
  anything else, so a RIB that stopped draining also stopped inbound accepts,
  session notifications and neighbor commands while readiness stayed green.
  The deletion's RIB cleanup now waits in order behind the full mailbox while
  the peer manager keeps working, including the removal of an interface-only
  neighbor. Every later ordered RIB update still goes after that cleanup.
  A new session for the same neighbor waits until the cleanup is admitted, so
  re-adding the deleted neighbor still waits for mailbox room.
  **Operator-visible:** while the cleanup waits, inbound connections that
  would admit a new dynamic neighbor, or that come in under the deleted
  neighbor's own label, are refused and counted as
  `bgp_inbound_connections_dropped_total{reason="rib_cleanup_pending"}`, a new
  series exported at 0 from startup. The neighbor reconnects on its own timer.
