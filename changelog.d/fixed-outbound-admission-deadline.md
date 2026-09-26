### Fixed

- Clear an outbound admission deadline once a pending slice stops waiting for
  writer capacity, including when source filtering emits no frames. This avoids
  a stale resource timeout after capacity returns and preserves a fresh timeout
  for a later stall.
