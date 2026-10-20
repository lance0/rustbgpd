# FastNetMon Community RTBH through rustbgpd

M126 runs the official FastNetMon Community package, unchanged, against
`rustbgpd-gobgp-bridge` and rustbgpd, with FRR as the upstream that receives
the blackholes. A replayed attack makes FastNetMon ban and unban one IPv4 and
one IPv6 host through its GoBGP action. Every assertion is made at FRR.
Control plane only: nothing is forwarded or dropped.

```bash
docker build --target dev -t rustbgpd:dev .
bash tests/interop/scripts/test-m126-fastnetmon-rtbh.sh   # exit 0 = PASS
```

The driver builds the lab image, deploys, runs about six minutes of phases,
and destroys the lab. It refuses a base image not built from this tree.

## Shape

| Node | Runs |
|---|---|
| `detector` | FastNetMon (AF_PACKET on a mirror veth), the bridge on `127.0.0.1:50051`, rustbgpd on its default owner-only Unix socket, and tcpreplay |
| `frr` | FRR, eBGP AS 65002, IPv4 and IPv6 unicast over one IPv4 session |

FastNetMon dials GoBGP at a hard-coded `localhost:50051`, so the detector and
the bridge share a node, as FastNetMon and gobgpd do in a stock install.
FastNetMon 1.2.9 speaks the GoBGP v3 API (`apipb.GobgpApi/AddPath`), the API
the bridge serves; its GoBGP client source is identical to the one the bridge
tests replay. Configuration: [fastnetmon.conf](fastnetmon.conf) (threshold
1000 pps, `ban_time = 20`, community `65535:666`, next hop `0.0.0.0` and `::`,
usage reports off), [rustbgpd.toml](rustbgpd.toml) (the bridge README's
`rtbh-only` export policy, `local_ipv6_nexthop`, default Graceful Restart),
and [frr.conf](frr.conf). [make_attack_pcap.py](make_attack_pcap.py) writes
one UDP frame per victim; tcpreplay loops them at 10,000 frames per second.

## Versions

| Component | Version |
|---|---|
| FastNetMon Community | 1.2.9 (`394fbe06`, the `v1.2.9` tag), official Debian 12 package, SHA-256 `108585308b91b8478a06741dbae179164467cc5ca5e0e45143ac5ed70c032448` |
| rustbgpd and the bridge | 0.79.0, built from the commit that adds this leg |
| FRR | 10.7.1 (`quay.io/frrouting/frr:10.7.1`) |
| tcpreplay | Debian 12 package |

## Results (2026-10-20, run of record)

| Phase | Observed at FRR |
|---|---|
| Ban | `203.0.113.7/32` next hop `10.0.0.1` and `2001:db8:66::7/128` next hop `2001:db8:126::1`, about 3 s after the replay starts. The received UPDATEs carry exactly `community blackhole` (65535:666) and AS path `65001`; next-hop self replaced FastNetMon's `0.0.0.0` and `::`. FRR's table adds `no-export` on receipt (RFC 7999 §3.2). |
| Unban | Both withdrawn 23 s after the replay stops: `ban_time` plus FastNetMon's 10 s unban watchdog. |
| rustbgpd restart (SIGTERM, then start 10 s later) | FRR keeps both bans as Graceful Restart stale routes through the outage. The session is back within 1 s of the start, rustbgpd sends End-of-RIB, and FRR has dropped the stale bans by the first poll; the bridge's next reconcile pass re-adds them 16 s after the start. **The upstream had no blackhole for about 16 s.** The gap is bounded by the bridge's reconcile interval (30 s default), not by FastNetMon, which never re-announces. |
| Bridge restart | Bans stay at FRR while the bridge is down; FastNetMon's later unban goes through the new bridge and both are withdrawn. |
| Unban while rustbgpd is stopped | FastNetMon's two withdrawals fail (`UNAVAILABLE`) 28 s after the replay stops, and the stale blackholes stay at FRR. rustbgpd is then started; its End-of-RIB flushes them within 1 s. The bridge retries its pending withdrawals, and neither ban reappears over the next 65 s. |

38 checks, 0 failed. Run-to-run timings vary by a few seconds with
FastNetMon's watchdog and the bridge's reconcile phase; an earlier run of the
same phases measured a 13 s restart gap.

## Scope

- One detector, one upstream, one victim per family. No scale claim.
- FRR as a default Graceful Restart helper. A peer without Graceful Restart
  withdraws the bans when rustbgpd stops; that case and an abrupt crash
  (SIGKILL, no restart marker) are not run here.
- FastNetMon sends each ban once; duplicate bans and unbans are covered by the
  bridge's own integration test, not this leg.
- Not in CI: the leg downloads a 95 MB vendor package and runs for about six
  minutes.
