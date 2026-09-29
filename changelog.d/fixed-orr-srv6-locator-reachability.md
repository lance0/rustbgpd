### Fixed

- ORR excludes SRv6 locator-only BGP-LS prefix advertisements from next-hop
  reachability when their Prefix Metric TLV is absent or malformed. A locator
  with a valid metric, including zero, remains usable; ordinary prefixes retain
  their existing default metric behavior. Raw BGP-LS reflection is unchanged.
