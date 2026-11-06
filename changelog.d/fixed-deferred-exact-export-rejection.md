### Fixed

- An update-group member's exact-export rejection of a unicast or VPN route
  now outlives the route's last source while RFC 4724 selection deferral
  holds the Loc-RIB best. Previously the rejection retired when the source
  withdrew, or when any End-of-RIB inside the hold pruned rejections. If the
  source then re-announced the route unchanged, the member's advertised
  count, advertised-route listing and BMP Adj-RIB-Out statistics included a
  route it was never sent once the hold released. Ungrouped peers were not
  affected. The same applies to labeled unicast, where
  `rbgp rib --prefix P advertised PEER --explain` reported a rejected route
  as advertised; labeled routes on the wire were not affected. When the
  release removes a held unicast, VPN, labeled unicast or EVPN row, the
  release now retires that row's rejections in the same pass, instead of
  leaving them until the next bulk prune.
