### Upgrade notes

- Rename these keys before upgrading, in `[[neighbors]]` and
  `[peer_groups.*]` tables and in `[[ethernet_segments]]`:
  `max_prefixes_ipv4` becomes `max_prefixes_ipv4_unicast`;
  `max_prefixes_ipv6` becomes `max_prefixes_ipv6_unicast`;
  `max_prefixes_received_ipv4` becomes `max_prefixes_received_ipv4_unicast`;
  `max_prefixes_received_ipv6` becomes `max_prefixes_received_ipv6_unicast`;
  `max_prefixes_out_ipv4` becomes `max_prefixes_out_ipv4_unicast`;
  `max_prefixes_out_ipv6` becomes `max_prefixes_out_ipv6_unicast`;
  `recovery_delay_secs` becomes `recovery_delay_seconds`.
  `rustbgpd --check` names the replacement for any old key it finds.
