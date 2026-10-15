### Added

- Log slow `/readyz` HTTP phases when accepting a connection through reading
  its request line, or starting its probe through writing its response, exceeds
  100 ms. Warnings separate handler startup, request-line reads, the core probe
  and response writes; existing probe-failure warnings also include elapsed
  context. Readiness status, response bodies and deadlines are unchanged.
