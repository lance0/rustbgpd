### Fixed

- Keep ordinary IPv4 BGP-LS topology prefixes usable for ORR when they carry
  an inapplicable SRv6 Locator TLV. IPv6 locator-only advertisements still
  require a valid Prefix Metric before contributing reachability.
