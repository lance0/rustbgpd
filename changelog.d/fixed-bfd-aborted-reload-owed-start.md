### Fixed

- An aborted configuration reload now always starts a BFD-coupled session
  that its rejected candidate held only because the candidate made the peer
  strict. When that session's command queue was full, the abort scheduled a
  retry of the `Start`, but it had already released the BFD hold, so the
  BFD level report that followed the abort canceled the retry. The peer then
  stayed enabled, unheld and Idle until BFD went Down and Up again or an
  operator disabled and re-enabled it. The hold now stays in place until the
  `Start` is queued, as it does when a reload commits; a genuine BFD Down
  still cancels the retry and holds the session.
  **Operator-visible:** after an aborted reload under session-queue
  backpressure, such a peer reconnects once its queue has room.
