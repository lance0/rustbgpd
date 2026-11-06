### Fixed

- After a planned Graceful Restart, interface-only (unnumbered) neighbors now
  take part in RFC 4724 selection deferral. Before, they received the Restart
  State bit and End-of-RIB grace but were never deferral waiters, so a spine
  whose Graceful Restart neighbors were all interface-only sent End-of-RIB to
  the first leaf before the other leaves' routes arrived, and that leaf
  removed the stale routes it held from us. Each one waits by interface and
  binds to the first session learned on it. An interface-only neighbor added
  at runtime now advertises Restart State 0, as a static neighbor added at
  runtime already did.
- The Graceful Restart marker written at shutdown with
  `warm_cache_checkpoint_on_shutdown = false` now takes its window from the
  committed runtime configuration. Before, it used the configuration loaded
  at boot or by the last SIGHUP, so a Graceful Restart neighbor added through
  gRPC or a config transaction left no marker (the next start was cold), and
  a `gr_restart_time` raised at runtime kept the shorter window.
