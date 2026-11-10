### Changed

- VPN, labeled-unicast, RT-Constrain, BGP-LS and EVPN replacement and
  withdrawal no longer sweep a large global attribute-intern table on every
  received UPDATE batch, and neither do local EVPN injection and withdrawal.
  They share the unicast schedule: collection runs after at most 4,096
  displaced routes (plus the triggering batch) or a one-second actor deadline,
  and small tables still collect immediately. Graceful-restart entry now
  sweeps once, after every affected family is re-selected, instead of up to
  five times.
  **Operator-visible:** `bgp_rib_attr_intern_global_size` can read above the
  live set count by the displaced sets still waiting for that sweep, and
  `bgp_rib_actor_work_duration_seconds{work_unit="attribute_gc"}` now also
  records deadline sweeps armed by these families.
