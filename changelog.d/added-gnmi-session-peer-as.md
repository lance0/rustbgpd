### Added

- gNMI `state/peer-as` reports the AS the session negotiated for a neighbor
  with `remote_asn = "external"` or `"internal"`, and omits the leaf while
  that session is not Established, instead of reporting 0. Numeric neighbors
  are unchanged. See [the gNMI reference](../docs/reference/gnmi.md).
