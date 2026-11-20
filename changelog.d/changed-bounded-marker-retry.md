### Changed

- After non-unicast selection release, receivers get End-of-RIB over several
  RIB turns. Outstanding release work runs every 10 ms. An uncontended VPN
  release visits up to eight receivers per tick. An RT-Constrain membership
  rebuild releases up to two completed holds per tick after the initial batch.
  A full writer keeps its ordinary retry deadline.
