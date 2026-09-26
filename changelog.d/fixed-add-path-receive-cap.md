### Fixed

- Enforce the configured Add-Path receive limit for negotiated IPv4/IPv6
  unicast paths per prefix. Block or shut down on excess retained path IDs
  according to `max_prefix_action`; warning mode reports attempts without
  limiting them. Existing path IDs can be replaced at the cap. The new
  `bgp_add_path_receive_limit_attempts_total` counter reports over-limit
  attempts by peer, family and action.
