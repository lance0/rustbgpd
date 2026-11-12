### Fixed

- Keep Stop and BFD-down prompt while a session is busy with its own work.
  Commands that arrive during an explicit outbound replay's admission wait or
  a shared update-group encode now wait in a small ordered queue instead of
  stopping the session from reading further commands. A queued session close,
  or a full queue, ends the replay with a retryable refusal or stops the
  encode at the next slice, where the group falls back to per-member
  encoding; routine commands no longer cost either. An inbound ORF
  ROUTE-REFRESH that finds the RIB mailbox full is held in order instead of
  blocking the session until the RIB drains, and a DEFER update is never
  turned into a plain refresh, so re-advertisement still waits for the
  peer's own refresh (RFC 5291). An export-policy update that finds the RIB
  gone now fails with an explicit error and keeps the previous policy.
