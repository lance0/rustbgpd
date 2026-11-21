### Changed

- After non-unicast selection release, receivers get End-of-RIB over several
  RIB turns. Outstanding release work runs every 10 ms. An uncontended VPN
  release visits up to eight receivers per tick. An RT-Constrain membership
  rebuild releases up to two completed holds per tick after the initial batch.
  A full writer keeps its ordinary retry deadline: a refused End-of-RIB is
  offered again one second later. Due retries then run eight receivers per
  10 ms tick until each has had one offer, and the next round waits another
  second. `bgp_rib_dirty_resync_total` no longer counts ticks that only retry
  or release End-of-RIB markers.
