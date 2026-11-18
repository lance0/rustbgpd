### Fixed

- A receiver's advertised EVPN table now grows its first route segment during
  the paced batch reserve that first needs more than 8,192 slots. Previously,
  with 1,024 new routes per batch, the ninth reserve grew the segment from
  8,192 to 16,384 slots and its first insert grew it again to 65,536. The
  reserve now grows directly to 65,536. Both old growth operations had
  8,192 initialized slots (1,179,648 bytes) per receiver. The allocator can
  grow in place. Withdrawn routes still leave slots available for reuse.
