### Fixed

- A peer whose session task panicked, or whose run loop returned an error,
  stayed down until it was reconfigured or the daemon restarted. The peer
  manager now replaces the session and starts it again, after publishing the
  dead session's `PeerDown` to the RIB. A dynamic peer or an inbound
  collision candidate is retired as if its session went Idle. A third crash
  of the same neighbor within ten minutes, counted across restarts, dynamic
  reconnects and inbound candidates, latches it disabled instead until
  `rbgp neighbor <peer> enable`; a reconfigure keeps the latch.
  **Operator-visible:** the neighbor's `last_error` names the crash, its time
  and the panic message while the peer is latched or for ten minutes after
  the crash, and the new `bgp_session_task_crashes_total{peer,interface}`
  counter, exported at 0 for each peer, counts crashes.
