### Fixed

- `/readyz` and `GetHealth` no longer report the peer manager as timed out
  while it waits for room in a full RIB mailbox. The peer manager queues
  several RIB updates that carry no reply: a policy cohort's export
  transition, discarding a prepared export destination, the `PeerDown` fence
  for a replaced or capacity-blocked session, and the deleted-peer marker.
  When the RIB's primary queue was full, as it can be during a large reload
  or a mass session flap, each of these sends stopped the peer manager from
  answering readiness probes until the RIB drained. It now answers them while
  it waits. The updates are still always delivered, never dropped for time.
  Neighbor reads are answered during the cohort transition send, as they
  already were during its reply wait. They stay queued behind the other
  sends, whose peer state is mid-change.
