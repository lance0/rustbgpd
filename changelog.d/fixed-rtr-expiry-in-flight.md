### Fixed

- RTR cache data now expires on time while a query is in flight or a reconnect
  is still connecting. Previously a cache that accepted a query and then stalled
  kept its expired VRPs and ASPAs in use until the 5-minute transaction deadline,
  and a connection attempt that never completed kept them indefinitely.
