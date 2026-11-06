# VPN FlowSpec controller and wire qualification

Functional receipt for scoped IPv4 and IPv6 VPN FlowSpec origination.
The family remains alpha; this receipt does not promote the v1 contract.

## Shape and fixed checks

- Candidate source: `fa44a729bae3a8269529371e40a6fad84bed9970`; binary SHA-256: `964661e2346fe76e738f0d64aa5c1ff1cf57e5e5d8c9fc531b937e641f66617a`.
- GoBGP: release 4.11.0, source `53ceb78fe284018ce83a92f3039198f0a86dc823`.
- Three isolated containers: candidate, a peer with both global and VPN
  FlowSpec families, and a peer with global families only. No host ports.
- Eleven initial rules cover global/VPN and RD isolation, IPv6 prefix and
  Flow Label components, and RD-inclusive payloads of 239 and 240 bytes.
- Require exact remote NLRI, RT and discard action, one scoped RT replacement,
  exact withdrawals, negotiated-family isolation, and receive/discard counters.
- Independently compare captured IPv6 offset-64 bytes with RFC 8956.
- Rollback uses released v0.81.0 at
  `eb1749d7018cd9691e4f4c9adef3b9adb830e9a8`, image
  `ghcr.io/lance0/rustbgpd@sha256:f8a6d62ced049e415d702e31c43cbd6dac62fa9bcfdd0f410938f3c6cc418a64`.
  Each scoped call must receive an application refusal and leave global
  rules and leases unchanged; matching global operations must succeed.

## Results

| Check | Result |
| --- | --- |
| GoBGP core, with IPv6 prefix offsets zero | PASS: 11 announcements and withdrawals, one RT replacement, exact scopes and attributes |
| IPv6 prefixes and Flow Label | PASS in VPNv6 with offset zero |
| RD-inclusive 239/240-byte boundaries | PASS in VPNv4 and VPNv6 |
| VPN receive/discard and global receive control | PASS: four VPN add/delete discards; global IPv6 add and withdrawal |
| Nonzero IPv6 offset, GoBGP receive | FAIL: valid RFC NLRI becomes an unknown component with null NLRI/attributes |
| Nonzero IPv6 offset, GoBGP send | FAIL: 13 pattern octets instead of 5 for length 104, offset 64 |
| Released-daemon rollback | PASS: 14 refusals, 14 unchanged snapshots, 14 matching global controls |
| Oracle regression tests | PASS: seven GoBGP and six rollback tests, including broken-input controls |
| Capture and cleanup | PASS: 99 core plus eight offset packets, zero kernel drops, no owned resources left |

The candidate emitted the exact RFC offset vector. The malformed vendor
UPDATE then caused NOTIFICATION 3/9 and one session flap, after the core
checks completed. The process exited zero because both probes completed;
nonzero-offset interoperability with this comparator remains FAIL.

The first GoBGP attempt was INVALID: its checker used `neighbor-ip` instead
of the release CLI's `peer-address`. The original failure is retained; the
fixed checker rejects wrong/missing peer addresses and passes all eight
captured views. The final run used harness commit
`170915fff1d7f5ca097c9d801840fbf22aa59218` with unchanged daemon source.

The rollback negative controls intentionally stop the daemon before a call,
stop it before the after-snapshot, or replace a scoped call with a global
mutation. Transport/read failures are INVALID; accepted global fallback is
FAIL. All three controls detect the broken condition. Two earlier harness
attempts were INVALID before mutation (empty address lookup and wrong health
field); their raw output is preserved in the rollback archive.

## Artifacts and limits

[Curated result](summary.json), [rollback rows](rollback-summary.json),
[rollback raw evidence](rollback-evidence.tar.gz), and
[GoBGP raw evidence](gobgp-evidence.tar.gz) retain the functional results and
negative controls. Archive hashes and exact executable/image pins are in the
curated result. Extract the archives to inspect requests, replies and captures.
Reproduction drivers are in `tests/interop/scripts/qualify-vpn-flowspec-rollback.py`
and `tests/interop/scripts/qualify_vpn_flowspec_gobgp.py`.

This is API, BGP wire and peer RIB evidence. IOS XR installation, action
execution, forwarding, performance, memory, scale and soak were not qualified.
The GoBGP nonzero-offset limitation remains separate from the offset-zero core.
