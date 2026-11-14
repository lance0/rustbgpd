### Fixed

- A session task that crashes while the RIB mailbox is full no longer holds
  the peer manager until the RIB has room. Replacing the crashed session
  waited for room to send its `PeerDown`. During an export-policy change or
  its rollback that wait ran where the change's two-minute RIB stall timeout
  was not checked, so a stalled RIB kept the change open until the
  30-minute settlement watchdog fenced the daemon and exited 70. The
  `PeerDown` is now queued, marked late, when the mailbox is full, and the
  stall timeout ends the change as before.
  **Operator-visible:** under a full RIB mailbox the replacement session's
  registration can reach the RIB before the crashed session's end; it
  supersedes the crashed session. That late end no longer purges
  graceful-restart retention owned by an earlier session of the neighbor,
  as for every other retired session. See
  [Settlement watchdog](../docs/how-to/settlement-watchdog.md).
