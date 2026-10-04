### Changed

- A clean export-policy reload builds its shared transition inventory during
  the unfenced destination prestage instead of under the RIB transition
  fence. Both update groups log the keys that churn touches after the walk
  starts, and the fence re-checks only those keys with the same table-drift,
  source-flip and rs-control checks. A missing, unfinished or unverifiable
  prestaged walk falls back to the fenced walk. On the 700-peer × 400,400-prefix
  reload-stall matrix leg, the fenced inventory step fell from about 173 ms to
  28 ms and the per-observer stall p50 from about 365 ms to 208 ms. Completion
  time, UPDATEs per member and VmHWM were unchanged (3 × 4 reloads per arm).
