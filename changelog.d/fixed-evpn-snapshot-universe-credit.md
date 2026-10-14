### Fixed

- Dormant EVPN recovery snapshots charge a shared key universe once per peer,
  including across retained snapshots and session records. Each record, mask,
  sparse allocation and temporary resize overlap remains charged; another
  peer keeps its own universe credit. This corrects premature per-peer budget
  refusals in recovery preparation and does not enable EVPN grouping.
