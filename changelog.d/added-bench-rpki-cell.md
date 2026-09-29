### Added

- `just bench-rpki-cell <out-dir> <base> <head>` measures the reloadstall
  route-server initial convergence with a static VRP table loaded, base
  against head in alternating runs. It generates a deterministic fixture
  (500,000 VRPs by default) in which every announced prefix is Valid, serves
  it from a digest-pinned StayRTR container on the CPUs in `RTR_CPUS`, and
  fails a cell unless the daemon reports the whole table before the first
  route arrives. It writes `cells.csv` with the RIB `route_chunk` work, daemon
  CPU time and convergence wall time per cell, plus a per-arm summary.
  `SMOKE=1` runs a small shape as a pipeline check. See
  [`bench/scale/rpki-cell/run-rpki-cell.sh`](../bench/scale/rpki-cell/run-rpki-cell.sh).
