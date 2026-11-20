### Fixed

- A session ending while a paced first-member update-group build holds an
  export-policy change for that peer no longer makes every other peer's
  UPDATEs wait for the rest of the build. The session end (peer down,
  graceful-restart entry, or a late end handed off by a dropped session) had
  to follow the pending policy change, and it was held at the head of the
  RIB's input queue, so nothing behind it was read until the build finished:
  about 2,000 actor turns on a 1M-route table. It is now kept in the ordered
  window that already holds later policy commands, and it runs right after
  the policy change commits and before any newer input.
  **Operator-visible:** unicast, labeled-unicast, VPN and EVPN route input
  from other peers keeps installing during such a build. Everything else on
  that queue (End-of-RIB, FlowSpec, BGP-LS and RT-Constrain input, reads,
  commands, other session changes, and the same peer's own later messages)
  still waits behind the session end, and the queue is held again, as
  before, when a timer for stale or refreshed routes falls due, when the
  passing input overflows the build's repair log, or when eight commands and
  session ends are already waiting. While the session end waits, a
  withdrawal from another peer can make the ended session's route best, and
  it is advertised until the build finishes; before, the withdrawn route
  stayed advertised for the same time.
