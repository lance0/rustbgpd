### Changed

- Reduce outbound distribution work by counting EVPN replacements without a
  second advertised-route lookup and keeping shared withdrawal and encoding
  handles on each update group's staged output. Outbound memory limits and
  attribute reclamation thresholds are unchanged.
