### Fixed

- A BFD Down that arrives during a configuration reload now stops the BGP
  session even when that session's command queue was full. The reload
  recorded the BFD hold and scheduled a retry of the session's `BfdDown`,
  but any later BFD report for the same peer, such as a level report,
  kept the retry from running until the reload finished. BGP stayed up
  over a path BFD had declared down for the rest of the reload. Inside a
  reload the retry now waits only for a queued BFD Up or remote
  AdminDown, which means the failure has already cleared; outside a
  reload it behaves as before.
  **Operator-visible:** BFD fast failure detection now takes effect during
  a long reload under session-queue backpressure.
