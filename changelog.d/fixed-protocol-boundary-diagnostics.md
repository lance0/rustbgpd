### Fixed

- BGP message length diagnostics now identify the violated per-type bound,
  including KEEPALIVE's exact 19 octets and the minimum OPEN, UPDATE,
  NOTIFICATION and ROUTE-REFRESH lengths. Enhanced Route Refresh markers
  report their exact 23-octet bound. Wire error responses are unchanged.
- Buffered RTR responses cannot renew data at or after its expiry. The client
  discards the response and flushes that cache's VRPs and ASPAs.
