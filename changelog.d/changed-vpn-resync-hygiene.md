### Changed

- Reserve the announce buffer when a VPN update-group member's dirty or forced
  resync replays the whole group table, hash the VPN and exact-export key sets
  on the resync path with the RIB's existing route hasher, and compare VPN
  recovery-proof keys as integers. Each reallocation of the unreserved buffer
  was one uncheckpointed copy of the table. **Operator-visible:** the longest
  RIB step without a readiness checkpoint during a full-table VPN resync is
  shorter, and each member's resync uses less CPU.
