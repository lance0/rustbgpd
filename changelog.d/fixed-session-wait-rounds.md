### Fixed

- Keep readiness responsive while retiring disconnected sessions and checking
  interface-only neighbor bindings, and wait on the affected sessions at once
  instead of 500 ms each in turn. A retirement round shares one 500 ms window
  from the start of its session waits; each interface-only port has its own.
  Healthy peers finish while stalled ones wait.
  **Operator-visible:** a session that has not stopped when its round's
  window ends is aborted, closing TCP without a Cease. The barrier that
  precedes removing a dynamic dampening source no longer waits for RIB mailbox
  room: it queues behind deferred RIB updates and is acknowledged within the
  same 5 s bound as before, after which the peer manager still stops. An
  interface-only session holding messages for a full RIB mailbox refuses a
  conditional retirement at once and is retried; a full mailbox makes the
  retention query retry. Operator reads now stay queued during the
  interface-only retention reply (at most 500 ms). See
  [operations](../docs/reference/operations.md).
