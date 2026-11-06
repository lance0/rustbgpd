### Fixed

- IPv6 FlowSpec prefix offsets encode only the matching bits, with RFC 8956
  bounds and padding handling for global and VPN rules. Injection rejects an
  IPv6 fragment value with DF (`0x01`, IPv4-only) or reserved bits set instead
  of accepting a value that matches every packet; received IPv6 rules ignore
  those bits. Injection rejects prefix lengths above the address-family limit
  instead of clamping them. Mixed IPv4/IPv6 VPN withdrawals keep separate wire groups.
