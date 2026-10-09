### Fixed

- Reflected labeled-unicast and VPN routes no longer carry the source's IPv6
  link-local next hop to peers on other links. RFC 4659 §3.2.1.1 and RFC 2545
  §3 (which RFC 4798 applies to labeled IPv6) allow the link-local half of a
  48-octet VPN or 32-octet labeled next hop only toward a peer sharing the
  link. As for IPv6 unicast, the received link-local is now forwarded only
  between interface-bound IPv6 link-local peers on the same interface; every
  other peer gets the 24-octet VPN or 16-octet labeled global next hop. This
  matches FRR's default.
  **Operator-visible:** a reflector or route server peering over global or
  IPv4 transport now sends the global-only VPNv6, labeled-IPv6, or
  IPv6-next-hop VPNv4 form where it previously passed the source's link-local
  through.
