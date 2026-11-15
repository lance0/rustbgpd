### Removed

- The deprecated config key spellings `max_prefixes_ipv4`,
  `max_prefixes_ipv6`, `max_prefixes_received_ipv4`,
  `max_prefixes_received_ipv6`, `max_prefixes_out_ipv4`,
  `max_prefixes_out_ipv6` and `recovery_delay_secs` are no longer accepted.
  The published JSON schema no longer lists them.
  **Operator-visible:** a config that still uses one fails `--check` and boot
  with an error naming the replacement key.
