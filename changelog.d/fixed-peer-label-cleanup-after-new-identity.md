### Fixed

- A neighbor's metric series no longer disappear or drop to zero when the
  previous identity at the same address is cleaned up late. When the RIB was
  behind, a deleted neighbor's RIB cleanup could run after a new neighbor at
  that address had started: a static neighbor re-added at once, a static
  neighbor replacing a dynamic neighbor kept for graceful restart, or a
  dynamic neighbor reconnecting. The cleanup then removed the new neighbor's
  `peer`-labelled series, such as `bgp_peer_admin_enabled`, `bgp_peer_info`
  and its session state. A dynamic neighbor kept for graceful restart that
  reconnected from another AS had the same problem in milder form: tearing
  down the kept identity set `bgp_rib_prefixes` and the graceful-restart
  gauges to zero for the address while the new session held routes. The
  late cleanup now leaves the address's series to the neighbor that holds it.
  A static neighbor that replaces a kept dynamic neighbor also keeps the
  series it seeds at start: the kept identity is now deleted before the new
  session starts, not after it.
