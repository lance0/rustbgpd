### Fixed

- A peer that fell behind on outbound updates while every route toward it
  went away now still receives its pending End-of-RIB and the answer to a
  ROUTE-REFRESH it sent meanwhile. Before, that refresh was dropped, and a
  Graceful Restart helper whose ORF-gated initial End-of-RIB waited for it
  never received the marker in that session, so it kept our withdrawn routes
  stale until its own timer expired.
