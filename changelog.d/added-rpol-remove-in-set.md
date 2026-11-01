### Added

- `.rpol` `remove <kind> in SET` and `remove <kind> not in SET` remove every
  arrived standard, large or extended community that is, or is not, a member
  of a community-set, patterns included: the RPL `delete community in` /
  `not in` forms. A well-known standard community is removed only by `in` and
  only when the set names it as an exact member, so an allow-list scrub keeps
  `NO_EXPORT`; likewise `remove ext-community not in` acts on route targets
  and route origins only, keeping encapsulation, color, EVPN and other
  extended communities. See
  [Removing by set membership](../docs/reference/rpol-language.md#removing-by-set-membership).
