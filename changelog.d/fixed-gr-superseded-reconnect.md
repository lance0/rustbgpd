### Fixed

- When a reconnect is replaced while another family still awaits
  End-of-RIB under GR or LLGR, retain fresh routes in the GR families
  that already completed. The replacement can refresh them before its
  own End-of-RIB or stale timer removes the remaining stale routes.
