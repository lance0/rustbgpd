### Fixed

- Unicast export explain reports `outbound_prefix_limit_reached` when a
  peer's outbound maximum withholds a net-new prefix, including the family,
  limit, and usage. Grouped peer explanations use the same admitted route
  view as advertised listings; admitted prefixes remain exportable at the
  limit.
