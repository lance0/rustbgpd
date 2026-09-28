### Changed

- Every stored route copy (Adj-RIB-In, Loc-RIB and RIB-Out) is 24 bytes
  smaller: the receive time is kept as a whole-second monotonic stamp and the
  per-session ASPA validation context as a small id into a shared table.
  Allocator-live RIB bytes fall 14.5% for a 900,000-route Adj-RIB-In and
  14.3% (106.4 MiB) on the 900,000-prefix route-reflector fanout shape. ASPA
  revalidation still uses each route's own session context, including for
  routes kept across a graceful restart.
  **Operator-visible:** a route's `received_at_epoch_seconds` remains an
  approximate wall-clock projection and can now read up to one second
  earlier than before.
