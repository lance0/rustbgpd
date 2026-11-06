### Fixed

- A neighbor created at runtime in a peer group that runs BFD now gets its BFD
  session, and a strict member is withheld until that session is Up; before,
  it ran without BFD until a restart. Deleting a strict-BFD neighbor and
  re-adding it without BFD, for example to change its ASN at runtime, no longer
  leaves BGP held behind the old strict session. The first BFD session in a
  socket family opens that family before the peer is added. Config
  transactions that add, delete or modify a static neighbor apply its BFD the
  same way, where they ignored it before; a failed transaction's rollback
  withholds a re-added strict peer until its restored session is Up. See
  [the reload matrix](../docs/reference/reload-matrix.md).
