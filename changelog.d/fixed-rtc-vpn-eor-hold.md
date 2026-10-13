### Fixed

- Toward a peer that negotiated RT-Constrain and starts with an empty RT
  membership, the VPNv4, VPNv6 and EVPN End-of-RIB now waits for the peer's
  RT-Constrain End-of-RIB, as
  [RFC 4684 §6](../docs/reference/rfc-notes.md#rfc-4684--rt-constrain-membership-matching)
  asks. Previously a PE that kept the route reflector's VPN routes as a
  graceful-restart helper, but whose RT-Constrain routes the reflector had
  not retained, received the VPN End-of-RIB before any VPN routes. It then
  swept the VPN routes it had kept and dropped that traffic until its
  interest re-arrived. A peer whose OPEN sets the graceful-restart Restart
  State bit is exempt: under RFC 4724 §4.1 it sends nothing, its
  RT-Constrain End-of-RIB included, until it has ours.
  **Operator-visible:** these markers are now sent after the peer's
  RT-Constrain End-of-RIB, or after a fixed 60-second cap when none arrives.
  A peer that never sends End-of-RIB, such as GoBGP without graceful
  restart, receives them 60 seconds after the session comes up. VPN routes
  still flow as soon as matching interest arrives, and other families'
  End-of-RIB is unchanged.
