### Fixed

- Keep `GetHealth` (and so `rbgp doctor`'s `daemon.healthy` check) inside its
  200 ms deadline while sessions deliver a reload's new exports. Its
  peer-manager half queries every session's state; each query's 100 ms bound
  started when its task first ran, which a runtime busy with the post-reload
  export burst delays, and the RIB half waited for that whole fan-out before
  it started. With 1,000 route-server clients the health RPC could return
  UNAVAILABLE (`peer manager probe timed out (200ms deadline)`) right after a
  SIGHUP that changed every client's export policy. The session fan-out now
  shares one deadline from its start, and the peer-manager and RIB halves of
  `GetHealth` and `/readyz` run concurrently under the unchanged 200 ms
  deadline.
