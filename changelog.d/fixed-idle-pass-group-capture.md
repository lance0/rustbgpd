### Fixed

- A distribution pass with no route change, such as each resync tick slice
  while any peer is dirty, no longer captures an admitted-key recovery proof
  for every clean update-group member whose outbound queue is full. The pass
  sends those members nothing, so each proof was released unused, and the next
  slice or one-second retry walked their group tables again. Such turns now
  cost less CPU and finish sooner. A pass that changes a route, a forced
  refresh and a complete EVPN feed still capture before the table moves.
