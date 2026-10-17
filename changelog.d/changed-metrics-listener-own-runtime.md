### Changed

- Serve `/metrics`, `/livez`, `/readyz` and `/dp-readyz` from a dedicated
  thread with its own single-threaded runtime, so saturated daemon runtime
  workers no longer delay accepting a probe or reading its request line.
  `/livez` and `/metrics` keep answering while those workers are busy;
  `/readyz` still asks PeerManager and the RIB on the daemon runtime, so their
  starvation still returns `503` within the 200 ms deadline. Readiness
  semantics, deadlines, supervision, bind-failure exit codes and
  `worker_threads` / `RUSTBGPD_WORKER_THREADS` are unchanged. The cost is one
  additional OS thread, plus a short-lived blocking thread while a scrape
  renders. See [operations](../docs/reference/operations.md#http-probes).
