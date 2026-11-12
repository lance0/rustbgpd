### Fixed

- A slow RIB answer to a conditional-advertisement change during a SIGHUP
  reload or a runtime policy catalog change no longer stops the daemon.
  Previously, if the RIB took longer than five seconds to acknowledge the
  install, re-observation or restore, the operation fenced
  `known_divergence` and exited 70, even though the RIB was still
  completing the work. The operation now waits for the acknowledgement,
  serving readiness and operator reads meanwhile, bounded by the
  [settlement watchdog](../docs/how-to/settlement-watchdog.md) budget. A
  request that cannot enter a full RIB mailbox within five seconds was never
  sent, and now rejects the reload or catalog change with no effect instead
  of fencing it.
