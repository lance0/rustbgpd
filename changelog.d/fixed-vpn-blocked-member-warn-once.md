### Fixed

- A grouped VPN member whose outbound channel stays full now logs
  `outbound VPN update deferred without admission` once, when it first
  falls behind, instead of once per VPN distribution pass. While its
  channel stays full, later passes also skip building that member's
  group deltas for a send that would fail; its resync still sends the
  full table and withdraws the keys it missed. **Operator-visible:** a
  full-table run with a slow receiver no longer floods the log with
  that warning.
