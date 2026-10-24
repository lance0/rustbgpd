### Added

- `[[bmp.collectors]] on_identity_conflict = "exclude"` lets a neighbor whose
  link-local address another BMP-monitored neighbor already holds, on a
  different interface, establish with its session left out of BMP instead of
  being refused. The default, `"refuse"`, keeps the earlier behaviour; any
  refusing collector refuses. An excluded neighbor is reported in
  `NeighborState.bmp_identity_excluded`, `rbgp doctor` (as
  `interface_only.<if>.bmp` for an interface-only neighbor, which also
  reports a learned address refused with `bmp_identity_conflict`) and
  `bgp_bmp_identity_excluded_neighbors`, and admissions are counted in
  `bgp_bmp_identity_conflicts_total{outcome}`. See the
  [configuration reference](../docs/reference/configuration.md).
