### Fixed

- `rbgp events sessions` and `ListSessionEvents` `lost` rows now end with
  the teardown cause recorded when the session left Established: the sent
  or received NOTIFICATION code, subcode and description with any valid
  RFC 9003 shutdown communication (sanitized), a transport cause, or
  `closed without NOTIFICATION`. The cause is no longer missing, and it is
  not taken from `Last Error`, which a later failed reconnect overwrites
  and a clean close leaves stale. The
  [peer-flap runbook](../docs/cookbook/peer-flap-triage.md) shows the
  output.
  **Operator-visible:** the `reason`/`summary` text of `lost` session
  events gains a `; <cause>` suffix; the JSON fields are unchanged.
