### Fixed

- Keep Stop and BFD-down prompt while a session is busy with its own work. An
  explicit outbound replay waiting for BMP or RIB admission now ends with a
  retryable refusal when any command other than a state or import-counter
  read arrives, so a Stop queued behind it no longer waits up to the
  five-second replay window. A shared update-group encode stops at the next
  slice for a session close, or when a second command queues behind a held
  one, and the group falls back to per-member encoding. An inbound ORF
  ROUTE-REFRESH that finds the RIB mailbox full is held in order with a plain
  refresh request behind it instead of blocking the session until the RIB
  drains. An export-policy update that finds the RIB gone now fails with an
  explicit error and keeps the previous policy.
