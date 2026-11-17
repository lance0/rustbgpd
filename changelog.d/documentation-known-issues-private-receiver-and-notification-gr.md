### Documentation

- [Known issues](../docs/reference/known-issues.md) now records that a
  disabled, administratively down, deleted or administratively reset
  Notification GR peer keeps its routes stale in v0.83.0 and earlier, and the
  limits that remain on long RIB turns toward private receivers: End-of-RIB
  hold releases other than selection release, ordinary UPDATE bursts, and
  whole-family sends outside the outbound credit.
