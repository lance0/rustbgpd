### Fixed

- `/readyz` and `GetHealth` no longer report the peer manager as timed out
  while it waits for room in a full RIB mailbox. Several RIB updates waited
  for mailbox admission without serving readiness: a policy cohort's export
  transition, discarding a prepared export destination, the `PeerDown` fence
  for a replaced or capacity-blocked session, and the deleted-peer marker.
  When the RIB's primary queue was full, as it can be during a large reload
  or a mass session flap, the peer manager stopped answering readiness probes
  until the RIB drained. Mailbox admission for these updates now answers
  readiness probes while it waits. The updates are still always delivered,
  never dropped for time. Neighbor reads are answered while the cohort
  transition waits for admission, as they already were during its reply
  wait. They stay queued behind the other updates, whose peer state is
  mid-change.
