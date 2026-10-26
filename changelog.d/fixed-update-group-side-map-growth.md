### Fixed

- Bound hash-table growth in update-group source attributes, runner-up routes,
  policy-denial residue, export memoization and policy-transition inventories.
  Route storage in Adj-RIB-In, Adj-RIB-Out and update-group tables now grows
  in fixed segments instead of copying the whole table when it doubles; at
  full-table size each copy stalled the RIB actor. This matters most for a
  group whose members are up before the feed arrives.
  Regroup snapshots reserve next-hop override storage sized to the overrides
  they can hold, and VPN denial updates visit the changed keys instead of
  scanning all denials.
