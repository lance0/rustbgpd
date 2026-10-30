### Fixed

- An identical FlowSpec re-add through `AddFlowSpec`, `AddLeasedFlowSpec` or
  `AddGuardedFlowSpec` returns `UNCHANGED` without re-inserting or
  re-selecting the rule, as unicast injection already did. With FlowSpec
  validation disabled, each such re-add previously rescanned every FlowSpec
  row, so a controller reconciling N rules did O(N²) work in the RIB actor.
  Leased re-adds still join and extend the owner's lease, and nothing is sent
  to peers in either case.
