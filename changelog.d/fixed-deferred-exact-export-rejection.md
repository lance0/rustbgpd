### Fixed

- An update-group member's exact-export rejection of a unicast or VPN route
  now outlives the route's last source while RFC 4724 selection deferral
  holds the Loc-RIB best. Previously the rejection retired when the source
  withdrew. If the source then re-announced the route unchanged, the
  member's advertised count, advertised-route listing and BMP Adj-RIB-Out
  statistics included a route it was never sent once the hold released.
  Ungrouped peers were not affected. A rejection whose
  held row the release removes now retires at the release.
