### Upgrade notes

- Config validation now rejects an export policy whose `set_next_hop`
  (`"self"` or an address) can reach an `ipv4_labeled_unicast`,
  `ipv6_labeled_unicast`, `l3vpn_ipv4_unicast` or `l3vpn_ipv6_unicast` route
  on the neighbor, peer group or dynamic range it is bound to. The rewrite
  used to be applied while the received labels were kept, and those labels
  are valid only at the received next hop (RFC 8277 §3.2.2), so the
  reflected traffic was black-holed. This is an operator-visible
  compatibility change: an existing configuration with such a binding fails
  to start, and a SIGHUP or API change carrying one is refused, until it is
  corrected. Bind the policy only to unicast peers, or in `.rpol` guard the
  action with `route.family == ipv4-unicast` or
  `route.family == ipv6-unicast`. The error names the family, the policy and
  the binding. Policy evaluation and explain no longer apply a next-hop
  action to a labeled or VPN route. See
  [route modifications](../docs/reference/configuration.md#route-modifications-set-actions).
