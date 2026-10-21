### Added

- Fast external failover: a directly connected eBGP session now closes as soon
  as the kernel confirms that the interface carrying it lost carrier, went
  administratively down, was removed, or lost the session's local address,
  instead of waiting for the hold timer. A session qualifies only when its own
  connection proves it: the local address is on that interface and the peer is
  inside its connected prefix, or the peer is a link-local neighbor on that
  interface. Multihop, loopback-sourced and iBGP sessions are untouched. The
  stop sends no NOTIFICATION, retains no routes under Graceful Restart or LLGR,
  and the session reconnects normally. A netlink overrun is treated as unknown
  and stops nothing. `fast_external_failover` turns it off per neighbor or peer
  group (hot-applied) or in `[global]` (restart-required); see
  [the configuration reference](../docs/reference/configuration.md#fast-external-failover).
  **Operator-visible:** the teardown cause names the interface and reason
  (`fast external failover: interface eth1 (ifindex 4) carrier lost`) in the
  neighbor's last error and the session-lost event, `bgp_session_down_total`
  counts it as `local_no_notification`, and
  `bgp_netlink_subscription_overruns_total` gains the
  `actor="fast_external_failover"` label value.
