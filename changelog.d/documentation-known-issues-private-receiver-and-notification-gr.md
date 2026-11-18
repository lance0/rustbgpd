### Documentation

- [Known issues](../docs/reference/known-issues.md) now records that a
  disabled, administratively down, deleted or administratively reset
  Notification GR peer keeps its routes stale in v0.83.0 and earlier, and the
  limits that remain on long RIB turns toward private receivers: ordinary
  UPDATE bursts, and whole-family sends outside the outbound credit for
  families other than IPv4 and IPv6 unicast. It also records the long turns
  of v0.83.0 and earlier that are fixed since: selection release, the other
  End-of-RIB hold releases, and IPv4 and IPv6 unicast whole-family sends.
