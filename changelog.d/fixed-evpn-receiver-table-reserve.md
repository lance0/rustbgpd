### Fixed

- A receiver's advertised EVPN table now sizes its route storage by one
  rule whether a batch reserves room first or a route is inserted alone.
  Outbound batches reserve room and then commit, and on that path the
  message that took a receiver past 8,192 EVPN routes copied its routes
  twice, 1.2 MB in the reserve and 2.4 MB in the first insert after it,
  outside the reserve's pacing. A first batch larger than 8,192 routes
  left 2.9 MB to copy the same way. The storage is now given its 65,536
  slots once, inside the paced reserve of the batch that first needs more
  than 8,192, and that step copies at most 1.2 MB; slots freed by
  withdrawn routes are reused before it grows. The evidence is a work
  count in unit tests, not a timing.
