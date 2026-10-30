### Fixed

- `ListPathExportDispositions` and `ExplainAdvertisedRoute` now compare a
  grouped route-server client's advertised route in that client's own
  form, after its route-server control communities are scrubbed and any
  prepend applied. An unchanged route that carries a control community
  reads `COMMITTED` instead of `not_yet_committed`, including a route frozen
  during Graceful Restart selection deferral. During deferral, explain
  reports an ORF installed during the hold that would filter a frozen
  injection as `selection_deferred` rather than `orf_filtered`. In each
  such explanation, `selection_deferred` is the single deciding stop, and
  the gate that would apply after release is named in its detail. See the
  [injection contract](../docs/reference/api.md#unicast-injection-contract).
