### Changed

- Size outbound UPDATE messages by encoded bytes. When routes that share one
  attribute set need more than one UPDATE, each UPDATE except the last is now
  full to within one route of the negotiated 4,096-byte or Extended Message
  limit for IPv4 and IPv6 unicast, where it previously carried a count found
  by halving and was often about half full. EVPN, VPN, labeled-unicast,
  BGP-LS, RT-Constraint and FlowSpec groups are sized from measured bytes per
  route: full when their routes are one size, possibly short when sizes vary.
  A peer receives the same routes and attributes in the same order, usually
  in fewer UPDATE messages, and the session discards far fewer trial
  encodings. Nothing for an operator to change; UPDATE counters for large
  same-attribute announcements and withdrawals read differently.
