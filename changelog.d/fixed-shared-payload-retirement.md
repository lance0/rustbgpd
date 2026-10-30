### Fixed

- Release a completed or torn-down unicast, VPN or EVPN update-group payload
  in bounded batches on the session that holds its last reference, instead of
  dropping the whole inventory in one session turn. Members completing at
  the same moment hand the inventory to exactly one of them. At about one
  million routes the single drop measured up to about 60 ms (unicast) and
  96 ms (VPN) when the payload owned its attribute sets.
