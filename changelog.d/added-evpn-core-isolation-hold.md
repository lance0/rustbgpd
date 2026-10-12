### Added

- Opt-in `[evpn_core_isolation]` (ADR-0140) holds the CE-facing links of bound
  Ethernet Segments administratively down while the PE has no Established or
  GR-retained L2VPN/EVPN session, or every configured `uplinks` entry has lost
  carrier, and at startup until EVPN has synced, so an all-active CE moves its
  traffic to the other ES member instead of hashing flows into a PE that drops
  them. Every member of a bound bond is taken down (the bond stays up); a
  segment with no remote ES peer seen while the core was up is not held. A
  hold releases after EVPN has stayed synced for `hold_after_sync_seconds`
  (default 10) or, with a warning, after `backstop_seconds` (default 180).
  Each admin-down is preceded by a durable identity receipt in
  `runtime_state_dir`; clean shutdown, the new
  `rustbgpd --release-core-isolation --runtime-state-dir DIR` stop-hook
  helper, and the next start raise only links whose recorded identity still
  matches, and report the rest as `ownership_ambiguous`. New
  `evpn_es_core_isolation_state{interface, state}` and
  `evpn_core_isolated{signal}` gauges and `rbgp doctor` checks
  `evpn.es.<interface>.core_isolation` and `evpn.core_isolation.uplinks`
  report it. See
  [`[evpn_core_isolation]`](../docs/reference/configuration.md#evpn_core_isolation).
