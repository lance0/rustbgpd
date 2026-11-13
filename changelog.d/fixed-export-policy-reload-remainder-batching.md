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
  **Operator-visible:** the changed peers are applied one export-policy
  group at a time, in the order of each group's first peer and at most 100
  peers per step. In a step those peers' sessions take the new policies,
  their RIB batch commits, and only then is the Route Refresh that follows
  an import-policy change sent to each of them, not right after the peer's
  own session step. A peer the reload has not reached yet still runs its old
  policies on its session and in the RIB, and a reload that fails part-way
  has touched only the sessions of the steps it reached. A group whose
  export chain reads a dataset shares only its first batch of 100; its other
  peers still resync one at a time. The `authoritative_batch_phase` log line
  appears once per batch during the remainder walk.
