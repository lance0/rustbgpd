### Fixed

- A neighbor's metric series no longer disappear or drop to zero when the
  previous identity at the same address is cleaned up late. When the RIB was
  behind, a deleted neighbor's RIB cleanup could run after a new neighbor at
  that address had started: a static neighbor re-added at once, a static
  neighbor replacing a dynamic neighbor kept for graceful restart, or a
  dynamic neighbor reconnecting. The cleanup then removed the new neighbor's
  `peer`-labelled series, such as `bgp_peer_admin_enabled`, `bgp_peer_info`
  and its session state. It now removes only the series the RIB itself
  writes, and the new neighbor's zero `bgp_exact_export_rejections_total`
  series are seeded again, for every family it is configured for, when its
  session is registered. A dynamic neighbor
  kept for graceful restart that reconnected from another AS had a related
  problem: tearing down the kept identity, or its restart timer expiring
  first, set `bgp_rib_prefixes`, `bgp_rib_adj_out_prefixes` and the
  graceful-restart gauges for the address to the kept identity's values or to
  zero, and removed its outbound prefix-capacity and `bgp_peer_update_group`
  series, while the new session was up or itself restarting. The address's
  series now stay the new session's. A static neighbor that replaces a kept
  dynamic neighbor also keeps the series it seeds at start, and the kept
  neighbor is deleted only once the new session has started, before the add
  completes, so none of its RIB counts carry over to the new neighbor. A
  static add whose session fails to start leaves the kept neighbor, its
  retained routes and its RIB gauges in place.
