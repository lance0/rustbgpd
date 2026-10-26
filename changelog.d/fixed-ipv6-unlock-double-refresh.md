### Fixed

- Reloading `local_ipv6_nexthop` avoids a second table encode when only an
  IPv6-unicast unlock needs exporting. Changes affecting already-sendable
  routes, including scoped IPv4 Extended Next Hop, still refresh them.
