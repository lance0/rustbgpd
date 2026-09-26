### Fixed

- When many inbound collision candidates were promoted in quick succession,
  for example while a route server's neighbors all reconnected at startup,
  each promotion resolved the next peer's queued collision inside itself. The
  nesting grew by one level per queued peer and could overflow a tokio worker
  stack, which aborted the daemon. Now, while one peer's collision is being
  settled, other peers' session notifications wait and are then handled in
  arrival order. Each peer's own notifications keep their order.
  **Operator-visible:** a burst of simultaneous inbound connections no longer
  aborts the daemon with `has overflowed its stack`.
