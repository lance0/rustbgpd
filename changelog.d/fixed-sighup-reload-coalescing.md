### Fixed

- A SIGHUP that arrives while a reload is running is no longer dropped.
  Each reload reads the config file early, so an edit written after that
  read and signalled during the reload was silently lost, while
  `systemctl reload` had already reported success. The signal now sets one
  pending follow-up, later signals fold into it, and once the running
  reload settles, whatever its outcome, exactly one follow-up reload
  re-reads the file. Signals already queued when a reload starts are
  served by it. Coordinated shutdown takes precedence and discards a
  pending follow-up with a warning. See
  [Configuration reload](../docs/reference/operations.md#configuration-reload-sighup).
