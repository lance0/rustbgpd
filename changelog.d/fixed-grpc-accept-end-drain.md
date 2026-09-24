### Fixed

- A gRPC listener whose socket became unusable no longer waits for every open
  connection to close before the daemon fail-stops. The transport drained
  open connections with no deadline once accepts ended, so a long-lived
  `WatchEvents` stream, or even an idle client connection, kept the daemon
  running on a dead listener until the client disconnected. The listener now
  gives open connections the one-second shutdown grace and then exits, and
  the existing gRPC server supervision exits 1. A TLS listener whose 64
  handshake slots are all held by stalled clients detects the failure only
  when a slot frees, up to the 10-second handshake timeout later.
