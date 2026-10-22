### Fixed

- A reload or policy edit that changes export policy no longer fails, or
  fail-stops the daemon with exit status 70, when a peer has just
  re-established but the RIB has not finished registering it for outbound
  updates. That window is common after a max-prefix restart on a large table.
  The change now skips the unregistered peer. Its registration installs the
  policy its session accepted, so the peer's first UPDATE already carries the
  new export policy. Dataset-driven export re-evaluation skips such a peer the
  same way. A rollback that finds no registration for a peer whose session
  state it observed now settles cleanly. An unknown session state still fails
  closed.
