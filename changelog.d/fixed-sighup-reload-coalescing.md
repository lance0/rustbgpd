### Fixed

- A SIGHUP that arrives while a reload is running is no longer dropped.
  Each reload reads the config file early, so an edit written after that
  read and signalled during the reload was silently lost, while
  `systemctl reload` had already reported success. The signal now sets one
  pending follow-up, later signals fold into it, and once the running
  reload settles, whatever its outcome, exactly one follow-up reload
  re-reads the file. Coordinated shutdown discards a pending follow-up
  with a warning. The new `rbgp reload` command sends SIGHUP to the daemon
  behind the local Unix socket, waits for the reload that read the config
  after its signal (a follow-up counts), prints the receipt `rbgp config
  last-reload` shows, and exits 0 for `complete`, 2 for `known_partial`,
  3 for `rejected_no_effect` or `task_failed`, and 1 on error or after
  `--timeout`. `GetLastSighupReload` records gain
  `started_monotonic_micros`, the reload's start on the daemon host's
  `CLOCK_MONOTONIC`, which `rbgp reload` uses to match its reload. See
  [Configuration reload](../docs/reference/operations.md#configuration-reload-sighup).
  **Operator-visible:** `bgp_sighup_reload_outcomes_total` replaces the
  `ignored_in_flight` outcome with `coalesced`, counted once per signal
  received during another reload; the follow-up reload's own outcome is
  counted separately. Dashboards or alerts that select `ignored_in_flight`
  must switch to `coalesced`. A coalesced signal no longer publishes an
  interim `GetLastSighupReload` record. The example systemd unit points
  automation that needs the outcome at `rbgp reload`.
