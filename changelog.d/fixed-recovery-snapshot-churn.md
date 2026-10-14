### Fixed

- Reuse live unicast/VPN update-group recovery key snapshots across route
  additions and withdrawals. Peers that become dirty in different passes share
  an older key universe with separate admission bits and bounded extra keys,
  avoiding repeated full-table snapshot allocations. Recovery limits and the
  conservative withdrawal fallback remain unchanged; private and regrouped flat
  proofs retain their existing resource limits.
