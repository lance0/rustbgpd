### Fixed

- `EnableNeighbor` (`rbgp neighbor <addr> enable`) on a peer whose session was
  already connecting or up tore the session down. The session sent
  NOTIFICATION FSM Error (code 5, subcode 0), restarted and lost its
  NOTIFICATION backoff streak, so a repeated or scripted enable flapped a
  healthy peer. As RFC 4271 §8.2.2 specifies, a start event outside Idle is now
  ignored: the RPC still succeeds, and the session, its counters and its backoff
  streak are left unchanged. On an idle peer, `enable` still starts the session
  and clears the backoff.
