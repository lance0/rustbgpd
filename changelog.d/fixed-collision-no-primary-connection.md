### Fixed

- An inbound connection that has received the peer's OPEN is no longer closed
  with Cease 6/7 as a "local wins" connection collision while the configured
  session has no connection of its own (Idle, Connect or Active). The BGP
  Identifier comparison now applies only against a session in OpenConfirm or
  OpenSent, and the session's state is read when the OPEN arrives rather than
  when the connection was accepted. Previously a neighbor with the lower BGP
  Identifier that connected first could be torn down on every attempt while
  the local outbound retry kept losing to it, so the session could stay down
  for as long as that race repeated. A session that is already Established
  still keeps its connection and the new one is closed. RFC 4271 §6.8 makes
  the OpenSent case optional: "A BGP speaker MAY also examine connections in
  an OpenSent state if it knows the BGP Identifier of the peer by means
  outside of the protocol." rustbgpd deliberately counts the identifier in the
  inbound connection's OPEN as that knowledge, as FRR does, so that two
  speakers following the same rule cannot both close their connections in a
  simultaneous open.
  **Operator-visible:** the collision log lines carry a `rule` field
  (`no_primary_connection`, `primary_established`, `primary_state_unknown` or
  `identifier_comparison`) and the primary's state, so a job or daemon log
  shows which rule decided each outcome.
