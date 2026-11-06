### Fixed

- An iBGP UPDATE received over IPv6 transport with IPv4 body NLRI and no
  NEXT_HOP attribute is now treated as withdrawn (missing well-known
  attribute, RFC 4271 §5.1.3 and RFC 7606) instead of installing the routes
  with next hop 0.0.0.0. Over IPv4 transport an iBGP peer may still omit
  NEXT_HOP, and the session address is used.
