### Changed

- Prometheus series for an IPv6 link-local neighbor now carry its scoped
  address as the `peer` label value, for example `peer="fe80::1%eth0"`, in
  every per-peer family: session, RIB, policy, max-prefix, BFD and BMP. The
  scope is always present, even when no other neighbor uses the address.
  Numbered neighbors keep their bare address, and label names are unchanged.
  See [the `peer` label](../docs/reference/operations.md#the-peer-label).
