### Fixed

- Service RIB readiness queries while an inbound enhanced route refresh
  finishes. End-of-RIB-Refresh and the refresh-window timeout withdrew the
  routes a peer did not re-advertise, reselected and distributed them in one
  uninterrupted step, so a peer closing a refresh window over a large table
  without re-advertising it could make the daemon miss its readiness probe.
  Key collection, each withdrawal, reselection and attribute reclamation now
  run under the same readiness owner as the End-of-RIB sweep, and windows
  that time out together are finished one owner at a time.
