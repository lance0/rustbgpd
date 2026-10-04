### Changed

- The update-group shared encoder groups an export-policy transition's
  announce inventory by source peer with a linear counting sort instead of
  comparison-sorting every route by source address before the first UPDATE.
  On the 700-member, 400,400-route reload-stall matrix leg, the first
  transition UPDATE now reaches members about 50 ms sooner after the
  transition commits, and the median per-reload stall p50 fell from 385 ms
  to 313 ms in an interleaved 3 × 4 reload A/B. Each member receives the same
  number of UPDATEs as before.
