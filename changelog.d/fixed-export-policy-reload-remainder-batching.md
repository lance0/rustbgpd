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
  **Operator-visible:** such a group is applied where its first peer stands
  in the walk, at most 100 peers at a time: those peers' sessions take the
  new chains, their RIB batch commits, and only then is the Route Refresh
  that follows an import-policy change sent to each of them, not between
  peers. A reload that fails part-way has touched only the sessions of the
  batches it reached. A group whose export chain reads a dataset shares only
  its first batch of 100; its other peers still resync one at a time. The
  `authoritative_batch_phase` log line appears once per batch during the
  remainder walk.
