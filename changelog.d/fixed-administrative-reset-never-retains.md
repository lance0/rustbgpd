### Fixed

- An administrative reset (`rbgp neighbor reset`, gRPC `ResetNeighbor`) no
  longer leaves the peer's routes retained under graceful restart or LLGR in
  two cases. When the peer negotiated the RFC 8538 N bit and draining queued
  output before the close raised Cease / Out of Resources, that plain Cease/8
  made both sides retain each other's routes; it is now sent as a Cease / Hard
  Reset carrying the Cease/8. When the reset found the session Idle after an
  earlier graceful-restart loss, it only restarted the connection and left
  the retained routes stale; it now purges them first.
  **Operator-visible:** a reset always drops the peer's routes until the peer
  resends them, and the NOTIFICATION event and sent-NOTIFICATION metric
  report subcode 9 for the wrapped Cease/8. Other teardowns, such as a TCP
  loss, a hold timer expiry or a NOTIFICATION from the peer, keep their
  retention.
  See [Reset a peer session](../docs/reference/operations.md#reset-a-peer-session).
