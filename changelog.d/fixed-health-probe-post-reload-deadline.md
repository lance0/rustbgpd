### Fixed

- Keep `GetHealth` (and so `rbgp doctor`'s `daemon.healthy` check) and
  `/readyz` inside their 200 ms deadline while sessions deliver a reload's new
  exports. `GetHealth` queries every session's state through the peer
  manager, which answered that fan-out in place, so a `/readyz` ping queued
  behind it waited for the whole fan-out. Each session query's 100 ms bound
  also started only when its task first ran, which a runtime busy with the
  post-reload export burst delays, and the RIB half of both probes waited for
  the peer-manager half before it started. With 1,000 route-server clients
  both probes could fail (`peer manager probe timed out (200ms deadline)`)
  right after a SIGHUP that changed every client's export policy. The health
  snapshot now runs detached from the peer manager, its session fan-out
  shares one deadline from its start, and the peer-manager and RIB halves run
  concurrently under the unchanged 200 ms deadline.
