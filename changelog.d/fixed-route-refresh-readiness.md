### Fixed

- `/readyz` and `GetHealth` no longer miss their 200 ms RIB deadline while
  the RIB answers a ROUTE-REFRESH with a full-table replay. With about
  400,000 prefixes, one replay held the RIB actor for roughly 180 to 280 ms
  without answering readiness. The replay now services the readiness lane at
  the same bounded checkpoints that initial table export uses. Replayed
  routes, End-of-RIB and Enhanced Route Refresh markers are unchanged, and
  ordinary queries and mutations still wait until the replay finishes.
