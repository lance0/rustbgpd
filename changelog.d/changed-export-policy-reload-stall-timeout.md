### Changed

- An export-policy reload is no longer rolled back because it took longer
  than two minutes. The walk over changed peers was bounded by one two-minute
  deadline in total, so at a full table a reload changing roughly 80 or more
  peers with per-neighbor export policies was rolled back although every
  step was succeeding, and every peer was then resynced a second time. The
  two-minute bound is now a stall timeout measured from the last RIB command
  that completed: a reload that keeps making progress commits, and one is
  rolled back only when a peer refuses or fails its step or the RIB
  completes no command for two minutes.
  **Operator-visible:** a large reload of per-neighbor export policies now
  takes as long as its work needs, about one full-table pass per such peer,
  and holds configuration changes and peer lifecycle commands for that time;
  the 30-minute settlement budget is the outer bound. Errors that named the
  `shared policy-walk budget` for the batched and paced steps now name the
  `policy-walk stall timeout`. Two log lines report a long walk:
  `authoritative policy walk started` and `authoritative policy walk in
  progress`, every ten seconds. See
  [Configuration reload](../docs/reference/operations.md#configuration-reload-sighup).
