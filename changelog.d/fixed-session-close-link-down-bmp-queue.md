### Fixed

- Close a session at once when fast external failover finds its interface
  down while the session is busy with a shared update-group encode or an
  outbound replay's admission wait. The link check now counts as a session
  close, so the encode stops at the next slice and the replay ends with a
  retryable refusal, instead of both finishing first. A link check that finds
  the interface up no longer takes a slot in the session's command queue.
- Stop a full BMP event queue from delaying a session close. A session
  leaving Established (Stop, BFD-down, hold-timer expiry, or a transport
  loss) no longer waits for queue room to report its Peer Down. The Peer Down
  is still delivered once the queue drains, after the peer's earlier Route
  Monitoring messages and before its next Peer Up.
