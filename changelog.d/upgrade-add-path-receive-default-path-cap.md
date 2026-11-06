### Upgrade notes

- An Add-Path receive peer without `add_path.receive_max`, or with
  `receive_max = 0`, no longer has unlimited IPv4/IPv6-unicast paths per
  prefix. Path IDs beyond 1024 for one prefix are withheld and counted; the
  session stays up. A peer that legitimately sends more paths per prefix
  needs an explicit `receive_max` (up to 65535), which also advertises the
  experimental Paths-Limit capability and follows `max_prefix_action`. Every
  action has a hard ceiling of `max(receive_max, 1024)` path IDs per prefix,
  past which IDs are now withheld instead of accepted. So
  `max_prefix_action = "warning"` warns only for IDs between `receive_max`
  and 1024; with `receive_max` of 1024 or more it blocks at the cap without
  warning, and `receive_max = 65535` admits up to 65,535 paths per prefix.
  Watch
  `bgp_add_path_receive_limit_attempts_total{action="block"}` after the
  upgrade to find such peers.
