### Fixed

- Reloading `local_ipv6_nexthop` onto an established eBGP session that
  withheld IPv6 unicast for lack of an IPv6 next hop now exports the family
  on the live session: the peer receives the full IPv6 unicast table and an
  End-of-RIB, with no session reset. Previously the family stayed withheld
  until the session reset. The establishment WARN now ends with
  `set local_ipv6_nexthop to export it` instead of advising a reset, and a
  new INFO line, `local_ipv6_nexthop now provides an IPv6 next hop:
  exporting IPv6 unicast`, records the restore. Route-server clients and iBGP
  sessions are unchanged.
  A superseded session's unlock is discarded and counted in
  `bgp_rib_stale_session_message_ignored_total` under the new
  `kind="family_sendable"` label.
