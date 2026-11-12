### Fixed

- A conditional-advertisement install, sent at the start of a SIGHUP reload
  or a runtime policy catalog change, no longer stops the daemon because the
  RIB is slow. An install that cannot enter a full RIB mailbox within five
  seconds was never sent, and now rejects the change with no effect instead
  of fencing `known_divergence` and exiting 70. An install that was sent now
  waits for the RIB's answer instead of failing after five seconds. A RIB
  that never answers still stops the daemon once the reload's
  [settlement watchdog](../docs/how-to/settlement-watchdog.md) budget
  expires, and a compensating restore that cannot be sent still fences.
