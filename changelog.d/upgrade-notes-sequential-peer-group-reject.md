### Upgrade notes

- A SIGHUP reload that changes a TCP-AO keyring or a listener MD5/GTSM
  setting together with a config-file-only peer-group field (for example
  `role`, `strict_role`, `prefix_orf_receive` or `disable_ipv4_unicast`) is
  now rejected before any effect, and `rustbgpd --diff` reports the
  `rejected` route. The reason names the group and field. Split the reload:
  apply the authentication change and the peer-group change in separate
  reloads. Outbound prefix maxima (`max_prefixes_out_ipv4`/`_ipv6`) on a
  group that already exists are applied by that reload and are not rejected;
  on a group the same reload adds, they are. A `tcp_mss` change that the
  reload pins until restart is not rejected. See the
  [reload matrix](../docs/reference/reload-matrix.md#sighup-reload-routes).
