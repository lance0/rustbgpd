### Fixed

- A dirty outbound resync that finds an empty export view now still sends a
  pending End-of-RIB and answers a ROUTE-REFRESH it was owing. Before, the
  refresh was dropped, and a Graceful Restart helper whose ORF-gated initial
  End-of-RIB waited for that refresh never received the marker in that
  session, so it kept our withdrawn routes stale until its own timer expired.
