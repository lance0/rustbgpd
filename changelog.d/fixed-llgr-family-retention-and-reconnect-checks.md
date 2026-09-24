### Fixed

- Long-Lived Graceful Restart now retains a family that the peer lists in its
  LLGR capability but not in its GR capability. RFC 9494 §4.2 deems the
  Restart Time zero for such a family, so its routes become LLGR-stale when
  the session goes down instead of being withdrawn. A peer that sends a GR
  capability with no families alongside LLGR is now LLGR-capable. When the
  peer re-establishes, a retained family that the new OPEN no longer lists in
  its GR or LLGR capability has its stale routes removed at once rather than
  at End-of-RIB or a timer (RFC 4724 §4.2, RFC 9494 §4.2). A GR capability
  that lists a family twice no longer deletes that family's routes at session
  down. `bgp_gr_stale_routes` now counts LLGR-stale routes as well as
  GR-stale ones at session down, End-of-RIB and Long-Lived Stale Time expiry,
  so an LLGR-only or partial-GR peer no longer reports zero or too few. See the [RFC notes](../docs/reference/rfc-notes.md#rfc-9494-42--llgr-families-outside-the-gr-capability).
  **Operator-visible:** routes from LLGR-only and partial-GR peers survive a
  session reset as least-preferred `LLGR_STALE` routes for the configured
  Long-Lived Stale Time.
