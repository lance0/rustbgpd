### Upgrade notes

- Link-local neighbors' metrics move to new series. A changed `peer` value
  starts a new series in Prometheus, so recording rules, alerts and dashboards
  that select a link-local neighbor by exact value (`peer="fe80::1"`) stop
  matching after the upgrade; change them to the scoped value
  (`peer="fe80::1%eth0"`). `by (peer)` joins between rustbgpd families are
  unaffected, and numbered neighbors' series do not change.
