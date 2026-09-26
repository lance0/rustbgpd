### Fixed

- Config history now recognizes rows written by a newer rustbgpd history
  format (`v4-` and later). Such a row lists as unreadable, keeps its sequence
  and its slot in the twenty-row cap, and is never evicted. While one exists,
  recording an accepted config into history is skipped with a warning instead
  of reusing the newer row's sequence; the config change itself still
  commits. See
  [ADR-0124](../docs/adr/0124-bounded-config-history-retention.md).
  **Operator-visible:** after a downgrade from a release with a newer history
  format, `rbgp config history` stops growing and the daemon logs
  `failed to record applied config in the config history` until the newer
  rows are moved aside.
