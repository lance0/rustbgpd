### Upgrade notes

- `max_prefixes_ipv4`, `max_prefixes_ipv6`, `max_prefixes_received_ipv4`,
  `max_prefixes_received_ipv6`, `max_prefixes_out_ipv4` and
  `max_prefixes_out_ipv6` are deprecated spellings. Existing configs keep
  parsing with the same meaning, and the JSON Schema still lists them (marked
  deprecated); rename them to the `_unicast` form shown in the
  [configuration reference](../docs/reference/configuration.md) at your next
  edit. Setting both spellings of one key in the same table is rejected.
  Tooling that matches the old names in `rbgp config diff` output, daemon
  written config, or the `rs-config-render` receipt (`clients[]` limit
  fields) must switch to the new names.
