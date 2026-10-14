### Fixed

- Dormant EVPN group recovery preparation rejects incomplete captures and
  invalid admission batches with a bounded, connection-fenced reset instead
  of stalling or asserting. Reset control retains execution acknowledgements
  and retries rejected or dropped handoffs. The fixed metric causes also
  include `capture_unavailable` and `admission_invariant`; the counter stays
  zero while production EVPN grouping is inactive. Provenance lookups use
  indexed owner ranges and charged running peer totals. This prepares
  recovery control and does not enable EVPN grouping.
