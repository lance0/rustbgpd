### Fixed

- Startup no longer fsyncs the config last-persist marker before it binds
  gRPC. The marker is a hint for `rbgp doctor`'s freshness check, but since
  the runtime-state hardening it was written durably, with three fsyncs on
  the boot path. On a slow disk that delayed the gRPC listener by seconds,
  long enough for activation tooling such as `rs-config-render activate` to
  give up. The marker is still replaced without following a symlink at its
  name or at its stage. A refused `runtime_state_dir` now also prints the
  directory and the reason on stderr before the daemon exits, not only in
  the structured log.
