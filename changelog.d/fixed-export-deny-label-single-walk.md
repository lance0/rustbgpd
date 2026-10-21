### Fixed

- An export-policy deny explained by `ExplainAdvertisedRoute`,
  `rbgp rib --prefix P advertised PEER --explain` or
  `ListPathExportDispositions` now takes its `"<policy>:<term>"` label from
  the evaluation that denied the route. The label previously came from a
  second walk of the policy, so a dataset refresh between the two walks could
  name a different `.rpol` term than the one that decided, beside
  `deny_validation` codes that described the deciding term.
