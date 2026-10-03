### Fixed

- VPNv6 route keys now hash their IPv6 address bytes through the hasher's
  byte-string path, as IPv6 unicast prefixes already do. Before this change,
  sequential VPNv6 /128 and /64 prefixes under one Route Distinguisher shared
  one hashbrown control byte and few starting buckets in the RIB's `FxHash`
  maps, so each lookup compared many candidate keys. VPNv4 hash values are
  unchanged; no configuration, API, or wire behaviour changes.
