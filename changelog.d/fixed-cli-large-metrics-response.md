### Fixed

- Allow metrics snapshots up to 64 MiB in `rbgp doctor`, `metrics`, `top`,
  and `evpn diagnose`, so per-peer metrics above gRPC's default 4 MiB limit
  remain available. Doctor retains the full metrics file in its diagnostic
  bundle and explicitly marks the system section partial if collection fails.
