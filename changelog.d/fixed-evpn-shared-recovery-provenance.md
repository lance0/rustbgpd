### Fixed

- Prepare shared immutable EVPN recovery key storage with separate admission
  masks and bounded sparse additions for each member. Captures retain only the
  actual old admitted projection, including when reusing an older key universe.
  Production EVPN grouping remains disabled pending complete-feed settlement
  and resource qualification.
