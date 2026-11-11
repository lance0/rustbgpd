### Fixed

- Best-path selection for VPNv4/VPNv6 and labeled-unicast no longer re-reads
  every stored Add-Path path of a key on each received UPDATE. When the
  UPDATE leaves the key's selected path alone, selection compares only the
  paths it announced or withdrew with that selected path, so the work per
  key no longer grows with the paths stored for it. An UPDATE that replaces
  or withdraws the selected path, and Graceful Restart, route refresh and
  session teardown, still select from all stored paths. The comparison also
  reads the attribute set's cached selection inputs instead of scanning the
  attribute list. Selection results, Add-Path send and Optimal Route
  Reflection staging are unchanged.
