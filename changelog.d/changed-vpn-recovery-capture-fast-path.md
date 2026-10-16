### Changed

- A full recovery capture for an update-group member that negotiates VPN no
  longer looks up every VPN route in the shared key pool when the group's VPN
  key set is unchanged since the pool was built; it admits the pool's VPN keys
  directly. This removes most of the extra RIB time that shared VPN capture
  added to mass-dirty recovery during route churn. Any key-set change still
  uses the exact lookups.
