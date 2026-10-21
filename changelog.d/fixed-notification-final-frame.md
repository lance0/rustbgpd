### Fixed

- A NOTIFICATION is now the final frame rustbgpd writes on a connection. An
  ordinary close (administrative stop or reset, daemon shutdown, a purge
  reset, a collision dump, or an error NOTIFICATION) previously wrote the
  Cease ahead of UPDATEs still queued for the peer and then sent those UPDATEs
  after it. Queued UPDATEs, including the EVPN withdraws shutdown drains
  before closing sessions, are now written first for up to 250 ms from the
  close; anything still queued then is discarded and the NOTIFICATION
  follows, so a slow peer still receives its Cease within the per-peer
  shutdown deadline. The Cease/Out of Resources teardown still discards its
  backlog. A shutdown that gives up on a peer which stopped reading also
  stops that peer's writer.
