### Added

- Session state, FSM event and BGP notification logs include the session ID
  and last installed TCP endpoints. Sent collision-resolution notifications
  also record the owning FSM state before teardown, allowing packet captures
  to be correlated with the closing connection.
