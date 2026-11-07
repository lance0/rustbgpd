### Upgrade notes

- An Add-Path receive peer for VPNv4/VPNv6 or labeled unicast now has the
  same per-prefix path cap as unicast: 1024 path IDs per RD + prefix or
  labeled prefix by default, or `add_path.receive_max` when set. Past the
  default cap the excess is withheld and counted; past an explicit
  `receive_max`, `max_prefix_action` applies as it does for unicast. Raise
  `receive_max` for a peer that legitimately sends more paths per prefix in
  those families.
- The "Add-Path receive limit exceeded" WARN log now names the NLRI in a
  `key` field instead of `prefix`, for every family (unicast included), and
  adds a `family` field. A VPN key prints as `RD prefix`, with the RD in its
  `ASN:nn` or `IP:nn` form. Update log queries that match the `prefix`
  field.
