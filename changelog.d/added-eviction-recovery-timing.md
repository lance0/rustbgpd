### Added

- `bgp_rib_outbound_eviction_recovery_seconds{outcome}` measures one
  receiver's recovery build after an owed-row cap eviction or when a dirty
  resync during an EVPN selection hold defers a rebuild until release.
  A refused data commit has its own series. See the
  [metric reference](../docs/reference/operations.md).
