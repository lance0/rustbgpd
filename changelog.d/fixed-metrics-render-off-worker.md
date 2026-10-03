### Fixed

- `/metrics` scrapes and the `GetMetrics` RPC (used by `rbgp doctor`) now
  gather and encode the registry on the blocking pool, one render at a time,
  instead of on an async runtime worker. A whole-registry render takes tens
  of milliseconds at 1000 peers; it previously stalled `/livez`, `/readyz`,
  gRPC operator reads and other tasks scheduled on the same worker for that
  long. Concurrent scrapes wait for the in-flight render. Metrics output is
  unchanged.
