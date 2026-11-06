### Fixed

- IPv6 FlowSpec prefix offsets encode only the matching bits, with RFC 8956
  bounds and padding handling for global and VPN rules. IPv6 fragment reserved
  bits no longer distinguish API keys and are ignored on receive. Injection
  rejects prefix lengths above the address-family limit instead of clamping
  them. Mixed IPv4/IPv6 VPN withdrawals keep separate wire groups.
