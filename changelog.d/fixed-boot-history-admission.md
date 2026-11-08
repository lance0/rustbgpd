### Fixed

- Record boot config history on the blocking pool after preparing its private
  directory, allowing gRPC to bind while history storage is slow. Persisted
  config mutations and SIGHUP remain serialized behind the recording attempt,
  including when its async waiter is canceled. History remains best-effort.
