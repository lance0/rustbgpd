### Changed

- The Linux dataplanes now resolve the netlink stack as one coherent family:
  `rtnetlink 0.24`, `netlink-packet-route 0.34`, transitive
  `netlink-proto 0.14`, with `netlink-packet-core 0.9` and `netlink-sys 0.9`
  unchanged. The upstream parser now accepts an `RTA_MULTIPATH` attribute
  with no next hops and zero-pads a short `IFLA_STATS` payload instead of
  failing the whole message. No rustbgpd code or raw-netlink escape hatch
  changed.
