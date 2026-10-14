### Fixed

- EVPN update-group preparation excludes peers that negotiated RT-Constrain
  from shared EVPN ownership and staging, while preserving their unicast and
  VPN update groups. Their EVPN view remains private and RT-filtered; stale
  membership state does not filter peers without negotiated RT-Constrain.
  Production EVPN grouping remains disabled, and grouped RTC still requires
  prior-membership capture and separate qualification.
