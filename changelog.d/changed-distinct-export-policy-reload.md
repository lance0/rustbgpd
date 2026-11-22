### Changed

- Export-policy reloads and rollbacks skip building the denial prefix set
  when no moving peer needs it. If every source route key survives, the
  transition also skips a second scan for withdrawals.
