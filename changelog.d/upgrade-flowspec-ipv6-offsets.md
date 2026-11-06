### Upgrade notes

- Nonzero IPv6 FlowSpec prefix offsets now use RFC 8956 pattern framing in
  both global and VPN rules. Peers using the former full-prefix framing are
  incompatible; pinned GoBGP 4.11.0 exhibits this defect. Qualify the peer
  before using nonzero offsets. Offset-zero IPv6 and valid IPv4 framing are
  unchanged.
