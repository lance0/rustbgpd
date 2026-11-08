### Security

- Bound repeated inbound warnings for non-negotiated MP_REACH families,
  scoped link-local IPv4 body NLRI, strict-peer next-hop rejection (per
  reason), and policy OTC rejection. Each class logs independently at its
  first and power-of-two occurrences per connection; metrics and route
  handling remain unchanged.
