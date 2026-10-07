### Added

- EVPN preference DF election now honors RFC 9785 Don't-Preempt recovery:
  recovering segments wait three seconds for remote Type 4 routes, inherit
  a protected reference PE's preference with DP=0, and restore configured
  values when becoming the reference. Equal-preference elections prefer
  DP=1 before the lowest originator IP. Explicit administrative DF changes
  still force a switchover; mixed DP and late remote routes cannot guarantee
  non-preemption. Single-active attachment circuits stay blocked during
  the recovery wait.
