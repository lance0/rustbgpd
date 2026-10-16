### Added

- Measure stalls in process instead of through sampled `/readyz` probes.
  `bgp_rib_actor_slice_seconds{stage}` times every poll of the RIB actor
  (`stage="actor_poll"`) and the slices between sampled readiness
  checkpoints, and `bgp_rib_actor_slice_max_microseconds{stage}` reports the
  longest slice since the previous metrics render. A 10 ms tokio probe
  records `bgp_runtime_scheduler_lateness_seconds`, and
  `bgp_runtime_worker_busy_microseconds_total{worker}` exports each runtime
  worker's busy time, so RIB actor occupancy can be told apart from runtime
  worker saturation. The histograms resolve 1 ms to 2 s with dense buckets
  around 25, 50, 100, 200 and 500 ms. The overview dashboard gains panels for
  both, and [the operations reference](../docs/reference/operations.md)
  documents them. Readiness semantics and deadlines are unchanged.
