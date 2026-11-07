### Upgrade notes

- An Add-Path receive peer without `add_path.receive_max`, or with
  `receive_max = 0`, no longer has unlimited IPv4/IPv6-unicast paths per
  prefix. Path IDs beyond 1024 for one prefix are withheld and counted; the
  session stays up. A peer that legitimately sends more paths per prefix
  needs an explicit `receive_max` (up to 65535), which also advertises the
  experimental Paths-Limit capability and follows `max_prefix_action`. Under
  `max_prefix_action = "warning"`, an explicit `receive_max` still warns past
  its value, but path IDs past `max(receive_max, 1024)` are now withheld
  instead of accepted. Watch
  `bgp_add_path_receive_limit_attempts_total{action="block"}` after the
  upgrade to find such peers.
