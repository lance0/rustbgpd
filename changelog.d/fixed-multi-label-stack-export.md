### Fixed

- A labeled-unicast or VPN route whose NLRI binds more than one MPLS label
  is no longer reflected. RFC 8277 §2.1 and §3.2.1 forbid sending such a
  route to a peer that has not negotiated the Multiple Labels Capability,
  and rustbgpd does not advertise it, so the route is withheld from every
  peer. A route already advertised with one label is withdrawn when it is
  replaced by a multi-label route. Multi-label routes are still received,
  stored and shown. Earlier releases reflected the stack unchanged.
  **Operator-visible:** each withheld route counts as
  `bgp_exact_export_rejections_total{reason="multiple_labels_not_negotiated"}`,
  a new reason value whose zero series exists only for the labeled-unicast
  and VPN families. See
  [RFC notes](../docs/reference/rfc-notes.md#rfc-8277--label-stacks-on-labeled-unicast-and-vpn-routes).
