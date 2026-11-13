### Fixed

- An export-policy reload no longer resyncs a full table once per peer for
  changed peers that share an export-policy change but are outside the one
  batched cohort. Each further group of two or more Established peers moving
  between the same pair of export chains is now applied as one RIB batch, the
  same one the cohort fallback uses, so a route server whose members fall
  into several policy groups no longer runs out of the two-minute walk budget
  and rolls the reload back at a few hundred changed peers. A compensated
  SIGHUP generation replays its prior chains the same way. A peer whose
  export change is its own still takes one RIB command, so a reload that
  changes about a hundred peers with per-neighbor export policies at a full
  table can still exceed that budget and roll back.
  **Operator-visible:** for those grouped peers the Route Refresh that
  follows an import-policy change is now sent once the group's RIB batches
  have committed, not between peers, and the `authoritative_batch_phase` log line appears
  once per group during the remainder walk.
