### Fixed

- The EVPN dataplane now re-reads the target VXLAN device from the kernel
  before it writes a remote-MAC, flood or FDB nexthop-group row. Before,
  it took the device's ifindex from the link inventory dumped at the start
  of the reconcile pass. If that VXLAN was deleted during the pass and
  another device was created with the same ifindex, the row for one VNI
  could be written to the other device. Such a write now fails and is
  retried after the next link dump.
