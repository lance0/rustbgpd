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

## Results (2026-10-20, three runs)

| Phase | Observed at FRR |
|---|---|
| Ban | `203.0.113.7/32` next hop `10.0.0.1` and `2001:db8:66::7/128` next hop `2001:db8:126::1`, 3-5 s after the replay starts. The received UPDATEs carry exactly `community blackhole` (65535:666) and AS path `65001`; next-hop self replaced FastNetMon's `0.0.0.0` and `::`. FRR's table adds `no-export` on receipt (RFC 7999 §3.2). |
| Unban | Both withdrawn 20-23 s after the replay stops: `ban_time` plus FastNetMon's 10 s unban watchdog. |
| rustbgpd restart (SIGTERM, then start 10 s later) | FRR keeps both bans as Graceful Restart stale routes through the outage. On the new session rustbgpd sends End-of-RIB, and FRR drops the stale bans. The bridge's liveness probe sees the daemon answer again and replays the bans; FRR received them **226-240 ms after End-of-RIB** in two runs (from FRR's millisecond log), and the once-a-second FRR poll never saw them missing. Before the probe, the bridge waited for its 30 s reconcile pass and the gap was 13-22 s. The gap still races End-of-RIB: it is bounded by the bridge's 0.5 s probe interval plus the daemon's gRPC start, not closed. |
| Bridge restart | Bans stay at FRR while the bridge is down; FastNetMon's later unban goes through the new bridge and both are withdrawn. |
| Unban while rustbgpd is stopped | FastNetMon's two withdrawals fail (`UNAVAILABLE`) 24-28 s after the replay stops, and the stale blackholes stay at FRR. rustbgpd is then started; its End-of-RIB flushes them within 4 s. The bridge retries its pending withdrawals, and neither ban reappears over the next 65 s. |

50 checks, 0 failed, on the head that adds this leg. Every ban, unban and
absence check also requires the session to be Established without a flap
since the last restart the driver caused: FRR's connection counters, and
rustbgpd's `bgp_session_established_total` and `bgp_session_flaps_total`.
Timings vary with FastNetMon's 10 s unban watchdog and the phase of the
bridge's reconcile pass.

## Scope

- One detector, one upstream, one victim per family. No scale claim.
- FRR as a default Graceful Restart helper. A peer without Graceful Restart
  withdraws the bans when rustbgpd stops; that case and an abrupt crash
  (SIGKILL, no restart marker) are not run here.
- FastNetMon sends each ban once; duplicate bans and unbans are covered by the
  bridge's own integration test, not this leg.
- Not in CI: the leg downloads a 95 MB vendor package and runs for about six
  minutes.
