### Fixed

- `/readyz` and `GetHealth` no longer report the peer manager as timed out
  shortly after a large SIGHUP reload. Reload settlement publishes the
  configured peer owners to the RIB, and the peer manager stopped answering
  readiness probes while it waited for that acknowledgement. After an
  export-policy change on 1000 peers, the RIB can take 1-2 s to acknowledge
  while it works through post-commit export updates. The peer manager now
  answers readiness probes during that wait. The 200 ms deadline is
  unchanged.
