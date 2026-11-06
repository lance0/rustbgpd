### Fixed

- Removing a dynamic-neighbor range now releases its admin-disabled
  members, as its enabled members are released when their sessions next go
  Idle. Before, a disabled member kept its dynamic-neighbor slot, refused
  delete, dropped its inbound connections, and `enable` restarted it
  although no range covered its address. `enable` on a dynamic peer that no
  configured range admits now fails with `FAILED_PRECONDITION` and changes
  nothing. See the
  [ADR-0086 amendment](../docs/adr/0086-dynamic-peer-group-reconfigure.md).
