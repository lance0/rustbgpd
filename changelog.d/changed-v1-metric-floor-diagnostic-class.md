### Changed

- The v1 inventory now lists a route-server and route-reflector metric floor
  under `metrics.stable_series`: 26 series covering session state, prefixes per
  canonical family, max-prefix, RPKI, reload outcome and readiness. The check
  compares each series' name, type and labels with its registration, and its
  pinned label values with production call sites. Series that expose RIB
  actor, scheduler, update-group and recovery internals are now classified as
  diagnostic under `metrics.diagnostic_series`, and carry no v1 compatibility
  promise. See the [v1 contract](../docs/reference/v1-stable-contract.md).
