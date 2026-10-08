### Fixed

- The EVPN dataplane now reads the VXLAN destination of each kernel FDB
  row it dumps. The netlink decoder returns `NDA_DST` in an `AF_BRIDGE`
  message as raw bytes, which the dump discarded, so on Linux every
  remote-MAC row appeared to have no destination and the reconciler's
  check of an owned row's destination against its route never saw a
  mismatch.
