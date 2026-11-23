### Fixed

- Route reflectors now update the ORIGINATOR_ID on unicast routes when the
  source reconnects with a new BGP Identifier. An ORIGINATOR_ID already
  carried by the route is preserved.
