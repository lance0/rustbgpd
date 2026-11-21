### Fixed

- An UPDATE, a withdrawal, a route injection or a source session going down
  no longer rebuilds the whole table of every update-group member that is
  waiting to be resynced in the same RIB actor turn. Those members were
  resynced inline, one after another, so with many members dirty after
  backpressure one unrelated UPDATE could hold every other peer's updates
  for seconds, and for minutes at full-table scale. The pass now leaves each
  dirty member to the resync tick, which rebuilds one member per slice
  within its poll budget, and records the change in the member's
  withdrawal residue as it does when the member's channel is full.
  **Operator-visible:** a dirty grouped member is resynced by the resync
  tick, about one second after it went dirty and then at the tick's backlog
  cadence, instead of by the next unrelated UPDATE, so it can stay dirty
  slightly longer. This includes members an export-policy dataset
  re-evaluation marks dirty. Passes that carry no route change, such as a
  ROUTE-REFRESH or operator replay, an RT-Constrain change or a policy
  cohort commit, still resync dirty members in their own pass. Ungrouped
  peers are unchanged.
