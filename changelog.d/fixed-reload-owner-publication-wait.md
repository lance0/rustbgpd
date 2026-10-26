### Fixed

- A SIGHUP reload or config transaction that keeps every configured neighbor
  and starts no session no longer waits for a RIB acknowledgement before it
  settles. That acknowledgement queued behind the reload's own post-commit
  export work: in a 200-peer, 100,000-prefix policy reload it held settlement
  for 34–46 ms after `config reload complete`, and larger tables queue more
  work ahead of it. Reloads that add, remove or re-key a neighbor, or start a
  session, still wait for the RIB.
