### Fixed

- Hold the primary connection's KEEPALIVE while admitting an inbound collision
  candidate before the primary reaches OpenConfirm. A higher remote BGP
  Identifier can then retire the primary before the peer establishes it and
  closes the other connection. Canceled admission and candidate retirement
  release the hold; sessions without a candidate are unchanged.
