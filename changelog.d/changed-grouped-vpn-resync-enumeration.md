### Changed

- Skip the per-peer VPN key-set build during a VPN update-group member's
  dirty or forced resync, and hash the labeled-unicast resync key set with
  the RIB's route hasher. A grouped member's VPN replay is assembled from the
  group table, so the set was only checked for emptiness; the member's VPN
  sources are now probed for one eligible key instead. **Operator-visible:**
  each grouped member's full-table VPN resync uses less CPU.
