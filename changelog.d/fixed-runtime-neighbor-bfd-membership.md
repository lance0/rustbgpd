### Fixed

- A neighbor created at runtime in a peer group that runs BFD now gets its BFD
  session, and a strict member is withheld until that session is Up; before,
  it ran without BFD until a restart. Deleting a strict-BFD neighbor and
  re-adding it without BFD, for example to change its ASN at runtime, no longer
  leaves BGP held behind the old strict session. The first BFD session in a
  socket family opens that family before the peer is added; if the BFD actor
  does not acknowledge it, the create reports an ambiguous outcome and BFD is
  fenced as after an uncertain reload. Config transactions that change BFD
  membership are still rejected. See
  [the reload matrix](../docs/reference/reload-matrix.md).
