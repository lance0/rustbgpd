### Upgrade notes

- The default EVPN `[[ethernet_segments]] df_preference` is now 32767, the
  value RFC 9785 §3 requires, instead of 32768. A highest-preference or
  lowest-preference segment that omits `df_preference` now ties with other
  implementations' default instead of winning (highest) or losing (lowest)
  against it, so the equal-preference tie-breaks (Don't-Preempt, then the
  lowest originator IP) decide the DF in mixed fleets. Set
  `df_preference = 32768` explicitly to keep the previous election.
  Default-modulo and highest-random-weight segments do not advertise
  preference and are unaffected; an explicit `df_preference = 32768` on them
  is still accepted.
