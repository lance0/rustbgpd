### Fixed

- Close two gaps in the coalescing of max-prefix warnings. While the peer
  manager resolved a collision and set other peers' notifications aside,
  each later crossing of a scope's warning threshold added another warning
  to that backlog. The backlog now holds one warning per session scope,
  counting every crossing. After the peer manager stopped, a crossing could
  also be added to a warning that would never be delivered, with no log
  line. It is now reported as a failed max-prefix warning notification.
