### Added

- Add a five-minute advisory for Established peers without outbound
  registration in Prometheus and `rbgp doctor`. The alert requires continuous
  observed absence; doctor reports current absence after five minutes of
  session uptime. Queued imports can legitimately defer registration without
  a fixed deadline. Unavailable or stale snapshots and unknown daemon field
  support remain unknown; membership evidence remains address-level for
  scoped peers.
