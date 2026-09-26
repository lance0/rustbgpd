### Fixed

- Peer-scoped gRPC reads that cannot find a neighbor during initial registration
  now return retryable `UNAVAILABLE` until the configured roster is installed,
  including policy-chain and concrete-neighbor gNMI reads.
