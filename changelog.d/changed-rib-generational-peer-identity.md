### Changed

- The RIB now identifies each neighbor by a compact generational handle
  instead of its address, so each stored route is 8 bytes smaller (104 bytes).
  A neighbor keeps its handle across a reconfigure; a deleted and re-added
  neighbor gets a new one, and messages from the deleted neighbor's sessions
  are dropped. The final best-path tie-break compares the peer address, then
  the interface name of a scoped IPv6 link-local neighbor, then the Add-Path
  identifier, so two neighbors on one link-local address select the same
  winner whatever order they were configured or connected in.
  **Operator-visible:** a route-listing page token now names the neighbor's
  handle; a token issued before the neighbor was deleted and re-added is
  rejected as belonging to another scope.
