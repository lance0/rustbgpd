### Fixed

- An inbound connection that collides with our own connection to the same
  neighbor now waits in `OpenConfirm` for the RFC 4271 §6.8 collision
  decision before it sends a KEEPALIVE. A connection that loses on BGP
  Identifier previously reached Established and then closed, so the neighbor
  saw the session come up and go down again. It is now closed with Cease 6/7
  from `OpenConfirm`, and it never registers with the RIB or reports
  Established.
  **Operator-visible:** the neighbor receives no KEEPALIVE on the losing
  connection. A candidate that gets no decision within 10 seconds is closed
  with a Hold Timer Expired NOTIFICATION and the neighbor can reconnect.
