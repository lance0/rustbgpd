### Added

- EVPN preference DF election now honors RFC 9785 Don't-Preempt recovery:
  recovering segments wait three seconds for remote Type 4 routes (after a
  daemon restart, also until an L2VPN/EVPN session is established and every
  established one has sent End-of-RIB, bounded at 30 seconds), inherit a
  protected reference PE's preference with DP=0, and restore configured
  values when becoming the reference. Equal-preference elections prefer
  DP=1 before the lowest originator IP. Explicit administrative DF changes
  still force a switchover; mixed DP and remote routes arriving after the
  wait cannot guarantee non-preemption. Single-active attachment circuits
  stay blocked during the recovery wait.
