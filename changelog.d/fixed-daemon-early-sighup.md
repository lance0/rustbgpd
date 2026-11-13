### Fixed

- A SIGHUP sent while `rustbgpd` is still loading its config or starting
  logging no longer terminates the daemon. The signal is held from the start
  of daemon boot until the reload handler is installed, then runs one reload,
  so config management that signals during boot no longer kills it.
  **Operator-visible:** the daemon logs `rustbgpd ready` once at the
  readiness boundary where it sends systemd `READY=1`. `rustbgpd --help` and
  the man page now describe exit 70 as the
  [settlement fail-stop](../docs/how-to/settlement-watchdog.md), recovered by
  restarting, and state that the daemon runs in the foreground with no
  pidfile, logs to stdout, and rewrites its config file canonically on the
  first persisted runtime change.
