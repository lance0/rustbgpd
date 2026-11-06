### Security

- A `TestPolicy` or `ComparePolicy` candidate with many compile errors took
  time quadratic in its size to render. Each diagnostic re-indexed every
  source, and the work ran inline on a gRPC worker. One request near the
  4 MiB cap could hold a runtime worker for hours, so health, RIB and
  neighbor RPCs timed out. Rendering now indexes the sources once and shows
  at most 50 diagnostics and 256 KiB of text, then a count of what it left
  out. The same limits apply to `rbgp policy check` output and to config
  load errors. These RPCs now compile and render on the blocking pool under
  a 30-second deadline. Each policy service runs at most two such compiles
  at once and answers further requests with `RESOURCE_EXHAUSTED`.
