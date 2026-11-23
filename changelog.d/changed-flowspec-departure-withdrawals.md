### Changed

- When a source departure leaves the FlowSpec table empty, clean receivers
  reuse their advertised rule keys for withdrawals, avoiding a copy of each
  rule's components.
