### Fixed

- A peer whose session task panicked, or whose run loop returned an error,
  stayed down until it was reconfigured or the daemon restarted. The peer
  manager now replaces the session and starts it again, after publishing the
  dead session's `PeerDown` to the RIB. A third crash of the same peer within
  ten minutes latches it disabled instead, until `rbgp neighbor <peer> enable`.
  **Operator-visible:** the neighbor's `last_error` names the crash, its time
  and the panic message, and the new
  `bgp_session_task_crashes_total{peer,interface}` counter counts crashes.
