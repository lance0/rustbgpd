### Fixed

- Keep session commands responsive while inbound updates wait for RIB mailbox
  capacity. A policy or configuration command now receives an explicit refusal
  before changing state, allowing later Stop and BFD-down commands to close the
  connection while the held updates retain their order before the session end.
  State reads and required Route Refresh requests remain available. Accepted
  starts wait for the held updates and can still be canceled by a later stop.
  Export-policy updates and IPv6 export unlocks also refuse a full mailbox
  before publishing local changes, so callers can retry without a partial
  configuration update.
