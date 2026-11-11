### Fixed

- Keep session commands responsive while RIB-bound messages wait for RIB
  mailbox capacity. A policy or configuration command sent to a session that
  is already holding messages now receives an explicit refusal before changing
  state, an outbound replay request is answered as unavailable so its caller
  retries, and a conditional retirement that would end the session is refused
  while one that keeps it is answered as before. Later Stop and BFD-down
  commands close the connection at once, and the held updates keep their order
  before the session end. State reads and required Route Refresh requests
  remain available. Accepted starts wait for the held updates and can still be
  canceled by a later stop. An export-policy update or IPv6 export unlock that
  meets a full mailbox is no longer waited for inside the session: its message
  is held in order, the acknowledgement follows RIB admission, and the session
  keeps reading commands meanwhile.
