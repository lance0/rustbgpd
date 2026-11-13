### Fixed

- A session task that panicked while Established left its routes installed
  and its session counted live in the RIB until the neighbor was deleted, a
  replacement session registered, or the daemon restarted. The session's
  drop now closes the epoch while unwinding too, with a `PeerDown` that
  withdraws the routes: a panic is a local failure with no session left to
  resume, so graceful restart does not retain them. A session task that was
  aborted or panicked while Established also emitted no BMP Peer Down, so
  collectors kept the peer up; the drop now queues one (the teardown reason
  the session latched, else reason 2, local close without NOTIFICATION)
  behind the events already sent, and counts it
  in `bmp_source_drops_total{reason="channel_full"}` when the BMP channel
  has no room.
