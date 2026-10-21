### Added

- `ListPathExportDispositions` rows carry `deny_validation`: for a
  `policy_denied` row, one `rpki_<state>` or `aspa_<state>` code for each
  validation state the deciding export-policy statement's match tests, so a
  controller can tell a route-origin-validation deny of an RPKI-Invalid
  blackhole from any other policy deny without parsing `detail`. Other rows
  leave it empty. See
  [export read-back](../docs/reference/api.md#export-read-back).
