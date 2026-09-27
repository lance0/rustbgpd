### Documentation

- The known issue "Fleet policy stats can time out during reload" is resolved
  at its measured scope: the
  [route-server flagship soak](../docs/soaks/soak-rs-flagship-24h-2026-09-26.md)
  on a build with owner-published counter reads passed every gate, with all
  17,551 `rbgp policy stats --direction both` reads through 48 reloads
  returning `ok`. The evidence is one IPv4-only soak at 1,000 peers × 400
  prefixes on one untagged main revision. The 2 s shared deadline and
  all-or-error result are unchanged. See
  [known issues](../docs/reference/known-issues.md) and
  [ADR-0136](../docs/adr/0136-owner-published-counter-reads.md), now Accepted.
