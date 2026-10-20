### Added

- Interop leg M126 runs the official FastNetMon Community 1.2.9 package
  against `rustbgpd-gobgp-bridge`, rustbgpd and FRR 10.7.1: a replayed
  attack bans and unbans an IPv4 /32 and an IPv6 /128, which reach FRR with
  BLACKHOLE (65535:666) and a next-hop-self address, through a rustbgpd
  restart, a bridge restart and an unban while rustbgpd is stopped. The
  `rustbgpd:dev` image now includes the bridge binary. See the
  [M126 receipt](../tests/interop/m126-fastnetmon-rtbh/README.md).
