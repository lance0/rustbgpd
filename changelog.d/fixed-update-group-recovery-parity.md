### Fixed

- Update-group distribution suppresses unchanged per-client-best substitutions
  when the winner changes, matching the private per-peer announcement sequence.
- Dirty unicast and VPN resyncs withdraw only keys actually admitted to each
  receiver, including across RT-Constrain changes and interrupted regroups.
  Shared tombstones could previously withdraw routes a receiver never received.
- Grouped exports preserve the prior admitted slot when OTC or exact encoding
  rejects its replacement. Fresh blocked routes no longer produce unknown
  withdrawals, and a rejected replacement withdraws the old alternate once.
