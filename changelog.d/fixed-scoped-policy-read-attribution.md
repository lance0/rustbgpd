### Fixed

- Policy reads selected by a scoped link-local neighbor (`fe80::1%eth0`) no
  longer return another interface's data when a reload moves that address to
  a different interface while the request is queued. `GetNeighborPolicyChains`,
  `ExplainImportPolicy`, `ListRejectedRoutes`, `TestPolicy` and
  `ComparePolicy` check the scope against the state that supplies the answer
  and return `NOT_FOUND` on a mismatch, as neighbor mutations already did.
  `GetPolicyStats` parses the selector and selects the import row by address
  and interface from one roster snapshot. Numbered selectors are unchanged.
