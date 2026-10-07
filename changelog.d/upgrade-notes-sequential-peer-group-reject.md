### Upgrade notes

- A SIGHUP reload that changes a TCP-AO keyring or a listener MD5/GTSM
  setting together with a config-file-only peer-group field (for example
  `role`, `strict_role`, `prefix_orf_receive` or `disable_ipv4_unicast`) is
  now rejected before any effect, and `rustbgpd --diff` reports the
  `rejected` route. The reason names the group and field. Split the reload:
  apply the authentication change and the peer-group change in separate
  reloads. See the [reload matrix](../docs/reference/reload-matrix.md#sighup-reload-routes).
