### Fixed

- An export-policy reload no longer resyncs a full table once per peer for
  changed peers that share an export-policy change but are outside the one
  batched cohort. Each further group of two or more Established peers moving
  between the same pair of export chains is now applied as one RIB batch, the
  same one the cohort fallback uses, so a route server whose members fall
  into several policy groups no longer runs out of the two-minute walk budget
  and rolls the reload back at a few hundred changed peers. A compensated
  SIGHUP generation replays its prior chains the same way. A peer whose
  export change is its own goes through the same batch, alone: the RIB then
  builds its new table and sends the difference instead of resyncing every
  route, which costs less than the single-peer command it replaces. A peer
  the batch cannot move that way (one that also sends a family other than
  IPv4 or IPv6 unicast, or whose policy reads the peer's own attributes) is
  applied by the paced commands that follow its batch, with the same result
  as before.
  **Operator-visible:** every changed peer's session receives its new
  policies before the first of those RIB batches. The Route Refresh that
  follows an import-policy change is sent once that peer's group has
  committed its RIB batches, not right after the peer's own session step,
  and the `authoritative_batch_phase` log line appears once per batch during
  the remainder walk.
