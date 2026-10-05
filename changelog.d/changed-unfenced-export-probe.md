### Changed

- Build clean export-policy transition payloads directly into shared route
  slices and probe them before the RIB fence. The fenced transition rechecks
  churn and encoder identity, retaining the full probe when the prepared proof
  is stale or the payload changes size.
