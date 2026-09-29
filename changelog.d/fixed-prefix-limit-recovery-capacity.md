### Fixed

- Raising or removing an outbound prefix limit now waits for outbound channel
  capacity before rebuilding the pending family replay. Repeated retry ticks
  retain recovery intent without rebuilding and dropping the same replay,
  while healthy peers continue to recover.
