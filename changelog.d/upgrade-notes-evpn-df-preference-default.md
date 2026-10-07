### Upgrade notes

- The default EVPN `[[ethernet_segments]] df_preference` is now 32767, the
  value RFC 9785 §3 requires, instead of 32768. A highest-preference or
  lowest-preference segment that omits `df_preference` now ties with other
  implementations' default instead of winning (highest) or losing (lowest)
  against it, so the equal-preference tie-breaks (Don't-Preempt, then the
  lowest originator IP) decide the DF in mixed fleets. During a rolling
  upgrade, PEs relying on the implicit default disagree until all are
  upgraded: under `highest-preference` a not-yet-upgraded rustbgpd PE
  (32768) beats an upgraded one (32767), and under `lowest-preference` the
  upgraded PE wins. DF ownership can therefore move as PEs restart; set
  `df_preference` explicitly on every PE of the segment before upgrading.
  Set `df_preference = 32768` explicitly to keep the previous election.
  Default-modulo and highest-random-weight segments do not advertise
  preference and are unaffected; an explicit `df_preference = 32768` on
  them is still accepted.
