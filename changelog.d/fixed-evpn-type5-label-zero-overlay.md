### Fixed

- An EVPN Type 5 route whose ESI or Gateway Address is an overlay index is
  now imported when its label is 0. RFC 9136 §3.1 lets the sender zero the
  label of an overlay-index route and requires the receiver to resolve it
  recursively. rustbgpd dropped such routes as `l3vni_mismatch`, so the
  remote tenant subnet was never installed. The route now resolves through
  its overlay index under the IP-VRF's L3VNI. A label-0 route with neither
  overlay index, and a non-zero label that differs from the IP-VRF's L3VNI,
  are still dropped. See
  [EVPN VTEP troubleshooting](../docs/how-to/evpn-vtep-troubleshooting.md).
