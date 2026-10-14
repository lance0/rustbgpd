### Fixed

- `ListAdvertisedRoutes` and `rbgp rib advertised <peer>` now agree with
  unicast export explain for an update-group member whose outbound queue was
  full. While the member has no admitted baseline, both return
  `FAILED_PRECONDITION` until its resync is accepted. The listing previously
  showed the group's desired routes as advertised in that window. A regrouped
  member that keeps its pre-regroup baseline is now listed from that baseline,
  which explain already used. See the
  [explain how-to](../docs/how-to/explain.md#export-explain).
