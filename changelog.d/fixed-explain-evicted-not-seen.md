### Fixed

- Import-policy explain no longer answers `not_seen` ("the peer has not
  advertised this prefix") for a prefix whose cached decision was evicted.
  Only the last 512 evicted keys were remembered, so once a session had
  pushed more than `cache_size + 512` distinct prefixes, older evicted
  prefixes read as never advertised. Each session now remembers every
  evicted key until reset, at about 19 B per evicted key and at most about
  38 MB per session; past that cap an unknown prefix answers `evicted`.
  See the
  [ADR-0073 amendment](../docs/adr/0073-import-policy-explain.md#amendment-2026-09-29-evicted-keys-are-remembered-exactly).
