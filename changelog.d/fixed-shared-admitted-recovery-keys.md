### Fixed

- Share immutable unicast/VPN recovery keys between grouped peers while keeping
  admission records separate. Reserve known capture sizes before walking a full
  table, retaining the existing per-peer and daemon bounds and conservative
  withdrawal fallback when a complete proof cannot be retained.
- Settle successful grouped initial dumps and refreshes when recovery proof
  reservation fails, avoiding an unnecessary second full-table replay.
