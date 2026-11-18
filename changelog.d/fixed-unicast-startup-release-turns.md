### Fixed

- The RIB processes an IPv4 or IPv6 unicast startup selection release in
  batches so it can service incoming updates while rebuilding the family.
  Each peer's initial End-of-RIB follows its admitted routes.
