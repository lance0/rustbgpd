### Changed

- Promote bounded VPN, labeled-unicast, RT-Constrain and EVPN best read RPCs
  into their scoped route-reflector roles; EVPN remains limited to Types 1–5.
  Deprecate the four older whole-table reads outside v1, retaining their
  signatures and behavior, and document each bounded replacement. Family and
  EVPN pages now clamp requests above 1000 rows rather than rejecting them.
  The additive `AddressFamily` values 8–12 select VPNv4/v6, labeled IPv4/IPv6
  and RT-Constrain; existing enum values are unchanged. EVPN peer-filter
  clients must verify the documented response metadata acknowledgement.
