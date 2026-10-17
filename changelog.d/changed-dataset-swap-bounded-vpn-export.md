### Changed

- A SIGHUP dataset content swap now also re-evaluates only the affected
  VPNv4/VPNv6 routes, matched by inner prefix or origin AS, instead of
  running the full export re-evaluation for VPN receivers. A small swap on
  a full VPN table no longer holds the RIB long enough for readiness to
  report a stalled export-policy transition. RT-Constrain receivers and a
  VPN selection still held by graceful-restart deferral keep the full
  re-evaluation. The `dataset export re-evaluation complete` log event
  gains `affected_vpn_keys`.
  See [Datasets](../docs/reference/rpol-language.md#refresh-failure-and-observability).
