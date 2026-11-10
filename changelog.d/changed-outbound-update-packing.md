### Changed

- Fill outbound UPDATE messages by encoded bytes. When routes that share one
  attribute set need more than one UPDATE, each UPDATE except the last now
  carries as many routes as the negotiated 4,096-byte or Extended Message
  limit holds, where it previously carried a count found by halving and was
  often about half full. A peer receives the same routes and attributes in
  the same order in fewer, fuller UPDATE messages, and the session builds
  each message once. Nothing for an operator to change; UPDATE counters for
  large same-attribute announcements and withdrawals read lower.
