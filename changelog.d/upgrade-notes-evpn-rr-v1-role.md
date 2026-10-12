### Upgrade notes

- The EVPN route-reflector promotion changes no configuration, default, RPC
  behavior or CLI output. Automation that wants the v1 promise should read
  reflected EVPN state through `ListReceivedEvpnRoutes` /
  `ListAdvertisedEvpnRoutes` (or `rbgp evpn received|advertised PEER --json`)
  one route type at a time, 1 through 5, follow `next_page_token`, and restart
  from an empty token after `ABORTED`. Whole-table `ListEvpnRoutes` /
  `rbgp evpn`, type 0 or 6 peer-view calls, EVPN explain and events keep
  working as alpha surfaces. The EVPN table gauges count the whole table,
  including any Type 6 routes, and `bgp_gr_stale_routes` can overstate stale
  routes until End-of-RIB or the stale sweep.
