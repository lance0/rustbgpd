### Fixed

- Sessions sending large VPN, labeled-unicast or EVPN tables no longer hold a
  tokio worker for tens of milliseconds per outbound slice. Announcements are
  grouped into UPDATEs through a hash index instead of a linear scan that
  compared freshly prepared attribute lists, each envelope's routes are
  released slice by slice instead of all at once after its last UPDATE, and
  a slice that overruns a 4 ms encode budget makes the next one smaller.
  **Operator-visible:** `/readyz` latency and other sessions no longer stall
  behind a full-VPN dirty resync on a small worker pool. UPDATE contents and
  per-route order are unchanged; under CPU pressure a large table may be
  split into more, smaller UPDATEs.
