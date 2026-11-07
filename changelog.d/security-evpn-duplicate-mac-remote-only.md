### Security

- EVPN duplicate-MAC detection now counts only MAC moves detected by local
  learning (RFC 7432 §15.1). Remote Type 2 announcements and withdrawals
  also counted. A BGP peer that repeatedly advertised a MAC learned on
  this VTEP could reach the threshold with no local activity. With
  `action = "suppress_local"`, that withdrew the local Type 2 and filtered
  remote FDB programming for the MAC for `recovery_seconds`. A local learn
  against a remote advertisement still counts, so a genuine duplicate MAC
  is still detected. See
  [`evpn_duplicate_mac_moves_total`](../docs/reference/operations.md).
