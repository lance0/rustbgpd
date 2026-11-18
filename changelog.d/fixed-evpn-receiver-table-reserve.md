### Fixed

- When an outbound commit reserves space for new EVPN routes under a
  readiness owner, it now grows the receiver's first route segment in that
  reserve. Previously, with 1,024 new routes per batch, the ninth reserve
  grew the segment from 8,192 to 16,384 slots and its first insert grew it
  again to 65,536. The reserve now grows directly to 65,536. Each old
  growth operation had 8,192 initialized slots (1,179,648 bytes) per
  receiver. The allocator can grow in place. The same sizing rule applies
  when an update group seeds a receiver's private table.
