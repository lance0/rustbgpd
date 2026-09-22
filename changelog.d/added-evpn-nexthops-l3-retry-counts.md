### Added

- `ListEvpnNexthops` and `rbgp evpn nexthops` now report
  `l3_orphan_nexthops_count` and `l3_pending_delete_count` (text output:
  `l3-orphan-nexthops`, `l3-pending-deletes`) for L3 (all-active Type 5)
  FDB nexthops. Previously an L3 nexthop or nexthop group whose kernel
  delete kept failing was retried but did not appear on any status
  surface, because the existing `pending_delete_count` and
  `orphan_nexthops_count` fields count only L2 FDB nexthop IDs. Those two
  fields keep their L2 meaning.
