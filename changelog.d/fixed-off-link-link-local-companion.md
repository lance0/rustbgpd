### Fixed

- An IPv6 next hop forwarded unchanged to an iBGP peer or route-server
  client no longer carries the source's link-local address to peers on
  other links. RFC 2545 §3 allows the link-local in a 32-octet next hop only
  when the speaker shares a subnet with both the next hop and the receiving
  peer. The received link-local is now forwarded only between
  interface-bound IPv6 link-local peers on the same interface; every other
  peer gets the 16-octet global next hop. This matches FRR's default. It
  applies to IPv6 unicast and to IPv4 unicast over Extended Next Hop. VPN
  and labeled families are unchanged.
  **Operator-visible:** a route server or reflector that peers over global or
  IPv4 transport now sends a 16-octet IPv6 next hop where it previously
  passed the source's 32-octet form through. A peer whose IPv6 route
  resolution depended on that forwarded link-local must resolve the global
  next hop instead.
