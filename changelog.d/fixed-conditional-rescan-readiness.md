### Fixed

- The RIB now answers readiness probes while it re-observes a
  conditional-advertisement condition after a dataset its
  `condition_policy` reads is swapped, or after a source peer's group or
  ASN changes. With a prefix-range condition that re-observation walks
  every Adj-RIB-In row under the range in one actor turn, and it served no
  readiness query until it finished. **Operator-visible:** the readiness
  endpoint stays answered through these turns; the turns themselves are not
  shorter, and condition state, routes and wire output are unchanged.
