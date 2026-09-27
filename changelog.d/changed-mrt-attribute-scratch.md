### Changed

- MRT snapshot encoding reuses one attribute-encoding buffer per snapshot
  instead of allocating a buffer for every path attribute of every RIB entry.
  Allocation calls during a snapshot encode drop by half, and encoding a
  400,400-path route-server table is about 13% faster. The MRT output is
  byte-identical ([receipt](../docs/perf/artifacts/mrt-attribute-scratch-2026-09/README.md)).
