### Fixed

- A SIGHUP reload no longer fails, or reports a completed dataset refresh
  as ambiguous, because a long export, import or RIB step used up the
  two-second allowance for retrying a missed session-state reply. Only the
  retries themselves now count against that allowance, so a peer whose
  state reply is briefly late after a slow full-table re-evaluation still
  gets its retry.
