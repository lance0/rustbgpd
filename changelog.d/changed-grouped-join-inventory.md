### Changed

- A peer joining an existing update group no longer walks the Loc-RIB and
  every Adj-RIB-In to build a prefix inventory before replaying the group
  table. The join scopes that inventory to the group's recorded residue
  (export-policy denials, OTC-blocked routes, runner-up entries) and the
  peer's own residue, which is all a grouped join consults. This shortens
  each join on the RIB actor, most on route servers with many overlapping
  Adj-RIB-Ins. The joiner's table, End-of-RIB, counters and
  `PolicyFiltered` events are unchanged.
