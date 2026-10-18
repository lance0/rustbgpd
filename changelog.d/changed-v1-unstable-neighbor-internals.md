### Changed

- The [v1 inventory](../docs/reference/v1-stable-contract.md) no longer pins
  the alpha TCP-AO neighbor fields (`tcp_ao`, `tcp_ao_health`, the generation
  fields, `tcp_ao_rotation_phase`, `tcp_ao_rotation_error`), the update-group
  diagnostics (`update_group`, `update_group_recovery_fallback`,
  `prefixes_sent_pending`, `selection_deferral.waiter_session_id`) or the
  unversioned `DiffRuntimeConfigResponse.diff_json` document; they are now
  explicitly unstable, in the protobuf and in the neighbor-detail JSON floor.
  `authentication` stays stable. Inventory role families use the canonical
  configuration labels (`linkstate`, `linkstate_vpn`, `l3vpn_ipv4_unicast`,
  `l3vpn_ipv6_unicast`), and the stable-surface checker rejects any other.
