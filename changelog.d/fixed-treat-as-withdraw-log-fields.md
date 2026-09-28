### Fixed

- The RFC 7606 treat-as-withdraw warning now counts the NLRI of every
  family the malformed UPDATE announced. An `MP_REACH_NLRI`-only UPDATE
  previously logged `announced=0` although its routes were withdrawn.
  **Operator-visible:** the warning adds `families` (per-family announced
  counts, such as `ipv6_unicast=1`), `next_hop`, `link_local_next_hop`,
  and `prefixes` (the first eight announcements) fields. The preceding
  `UPDATE validation error` warning adds `attr_type`, the attribute type
  code that failed validation.
