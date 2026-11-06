### Upgrade notes

- An Add-Path receive peer for VPNv4/VPNv6 or labeled unicast now has the
  same per-prefix path cap as unicast: 1024 path IDs per RD + prefix or
  labeled prefix by default, or `add_path.receive_max` when set. Past the cap
  the excess is withheld and counted. Raise `receive_max` for a peer that
  legitimately sends more paths per prefix in those families.
