### Changed

- The update-group shared encoder groups an export-policy transition's
  announce inventory by source peer with a linear counting sort instead of
  comparison-sorting every route by source address before the first UPDATE.
  On the 700-member, 400,400-route reload-stall matrix leg, the first
  transition UPDATE now reaches members about 50 ms sooner after the
  transition commits (floor 55 ms to 6 ms). In the same interleaved 3 × 4
  reload A/B, the median per-reload stall p50 was 385 ms before and 313 ms
  after, with overlapping run ranges. Each member receives the same number
  of UPDATEs as before.
