### Fixed

- Deleting a neighbor no longer stops the peer manager while the RIB mailbox
  is full. Operator deletes, reconcile, dynamic-neighbor auto-removal and
  retained-identity expiry used to wait for mailbox room before handling
  anything else, so a RIB that stopped draining also stopped inbound accepts,
  session notifications and neighbor commands while readiness stayed green.
  The deletion's RIB cleanup now waits in order behind the full mailbox while
  the peer manager keeps working. A new session for the same neighbor, and
  every later ordered RIB update, still goes after that cleanup.
