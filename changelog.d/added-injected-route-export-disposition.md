### Added

- `InjectionService.ListPathExportDispositions` reports, for one route added
  with `AddPath` and named by its `(prefix, prefix_length, path_id)` key, one
  export disposition per Established peer: committed to the peer's
  Adj-RIB-Out, withheld with a bounded reason (for example
  `family_suppressed:missing_ipv6_next_hop`, `export_policy`,
  `outbound_prefix_limit`, `exact_export_rejected:<reason>` or
  `not_selected`), or pending. A route for the same prefix from another
  source never counts as this route's export, and a committed disposition
  does not mean the peer received the route. Peers are paged in address
  order. The method is a `sensitive_read` and joins the v1 inventory with
  `AddPath` and `DeletePath`. See the
  [export read-back](../docs/reference/api.md#export-read-back) reference.
