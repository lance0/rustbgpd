### Fixed

- Labeled IPv6 and VPNv6 export policies now discard the received link-local
  next hop and its interface scope when a `Specific` action changes the primary
  next hop, including Add-Path advertisements. Same-interface forwarding keeps
  its valid companion when the primary next hop is unchanged.
