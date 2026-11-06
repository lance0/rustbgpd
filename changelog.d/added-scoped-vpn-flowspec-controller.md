### Added

- IPv4 and IPv6 VPN FlowSpec controller origination with explicit Route
  Distinguisher identity and Route Target attributes. Plain, leased and
  guarded mutations, list views, lease pagination and export dispositions
  preserve the scope; unspecified listings still select global FlowSpec only.
  `rbgp flowspec` accepts VPN families, `--rd` and typed `--route-target` values.
  It rejects VPN scope on non-VPN mutations before sending an RPC, preventing
  older daemons from silently treating those requests as global rules.
  The new API fields and families remain outside the v1 inventory.
- Opt-in `l3vpn_ipv6_flowspec` negotiation, `vpnv6-flowspec` policy matching
  and per-family telemetry. Received VPN FlowSpec is decoded and discarded.
  `rbgp doctor` excludes both VPN families from inbound prefix-bound warnings.
  This adds no VRF import, reflection or forwarding guarantee. See the
  [controller API](../docs/reference/api.md#vpn-flowspec-controller-api).
