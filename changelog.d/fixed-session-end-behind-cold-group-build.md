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
  **Operator-visible:** routes from other peers keep installing during such a
  build. The order of one peer's own messages is unchanged; a new session of
  the same peer that arrives before the commit still waits at the head of the
  queue, as before. At most eight commands and session ends are kept this
  way; beyond that the previous behavior applies.
