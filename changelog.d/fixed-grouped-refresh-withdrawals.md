### Fixed

- When an update-group member owes withdrawals and lacks a complete record of
  its advertised routes, its unicast or VPN route refresh now follows resync.
  The same applies after such a member leaves its group, or joins one from a
  private table, before it refreshes. The peer receives its withdrawals before
  the refresh can purge those routes; before, it received one redundant
  withdrawal after End-of-Route-Refresh.
  **Operator-visible:** while another unicast or VPN family holds the peer's
  resync under selection deferral, the refresh answer waits for that hold to
  release, at most until the selection-deferral timeout. Before, it was
  answered at once.
