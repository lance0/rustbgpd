### Fixed

- Unicast export reconciliation and final-owner payload retirement now service
  dedicated readiness probes while preserving ordinary read and mutation fences.
  Shared payloads remain immutable, and readiness deadlines are unchanged.
