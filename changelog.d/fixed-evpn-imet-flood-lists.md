### Fixed

- The EVPN dataplane now reads the VXLAN destination of each kernel FDB
  row it dumps. The netlink decoder returns `NDA_DST` in an `AF_BRIDGE`
  message as raw bytes, which the dump discarded, so on Linux every
  remote-MAC row appeared to have no destination and the reconciler's
  check of an owned row's destination against its route never saw a
  mismatch.

- BUM traffic now reaches remote VTEPs. A VTEP originated its own Type 3
  IMET but ignored received ones, so broadcast, unknown-unicast and
  multicast frames from local hosts had no VXLAN destination unless the
  operator added static flood rows. Each received IMET with an
  ingress-replication PMSI that passes the instance's import check now
  programs one `00:00:00:00:00:00 … self extern_learn` row on the
  instance's VXLAN port (with `src_vni` on SVD ports); a withdrawal
  removes the row. IMETs with another PMSI tunnel type are skipped with a
  logged reason.
  **Operator-visible:** a VNI that still has a static zero-MAC row
  without `extern_learn` is left alone and logged as foreign; delete those
  rows to hand the flood list to the daemon. See
  [BUM flooding](../docs/how-to/evpn-vtep-setup.md#bum-flooding-ingress-replication).
