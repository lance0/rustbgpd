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

The driver builds the lab image, deploys, runs about seven minutes of phases,
and destroys the lab. It refuses a base image not built from this tree. Set
`M126_LAB` to give a run its own lab name when another run shares the host.

Phases 1-4 run with rustbgpd's default configuration and record the restart
gap as the control. Phases 5 and 6 repeat the restart cases with
[`gr_eor_grace_time`](../../../docs/reference/configuration.md#planned-restart-end-of-rib-grace-window)
`= 40` on the FRR neighbor, in a copy of the configuration that
`rustbgpd --check` validates first. Phase 7 repeats the restart with a 100 s
window and the bridge listed in
[`gr_eor_replay_owners`](../../../docs/reference/configuration.md#planned-restart-end-of-rib-grace-window),
so the bridge's replay-complete signal, not the timer, releases End-of-RIB.

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
| rustbgpd restart (SIGTERM, then start 10 s later) | FRR keeps both bans as Graceful Restart stale routes through the outage. On the new session rustbgpd sends End-of-RIB, and FRR drops the stale bans. The bridge's liveness probe sees the daemon answer again and replays the bans; In this lab, with two tracked bans, FRR received them **226-443 ms after End-of-RIB** across three runs (from FRR's millisecond log; the slowest on a loaded host). That is a measurement of this shape, not a bound: the replay time grows with the number of tracked bans and with RPC latency. Before the probe, the bridge waited for its 30 s reconcile pass and the gap was 13-22 s. The replay still races End-of-RIB, so the gap is narrowed, not closed. |
| Bridge restart | Bans stay at FRR while the bridge is down; FastNetMon's later unban goes through the new bridge and both are withdrawn. |
| Unban while rustbgpd is stopped | FastNetMon's two withdrawals fail (`UNAVAILABLE`) 24-28 s after the replay stops, and the stale blackholes stay at FRR. rustbgpd is then started; its End-of-RIB flushes them within 4 s. The bridge retries its pending withdrawals, and neither ban reappears over the next 65 s. |
| rustbgpd restart with `gr_eor_grace_time = 40` | FRR keeps both bans through the outage. At no poll during the 55 s after the start was a ban missing without a withdrawal UPDATE in FRR's log. The bridge's liveness probe saw the new daemon incarnation and replayed at once: both bans were fresh at FRR 2 s after the start (1 s polls; the driver requires at most 5 s, against the 30 s reconcile pass that refreshed them in earlier runs), and FRR received End-of-RIB for IPv4 and IPv6 at 40 s, the end of the window. rustbgpd logged the timed release. The only removal was FastNetMon's own IPv6 unban mid-attack (below). |
| Unban while rustbgpd is stopped, window on | The lifted bans stay at FRR as stale routes until the window releases End-of-RIB: still stale 40 s after the start and removed at 41 s. Neither reappears over the next 35 s. |
| rustbgpd restart with a 100 s window and `gr_eor_replay_owners = ["gobgp-bridge"]` (2026-10-21) | The bridge's probe saw the new incarnation, replayed both bans and signalled `MarkReplayComplete`; rustbgpd released End-of-RIB on that signal. Judged on FRR's millisecond log: each family's replayed announcement precedes its End-of-RIB (IPv6 by 40 ms; IPv4 in the same millisecond, earlier in log order), and End-of-RIB for both families arrived within the first second after the start, against a deadline at 100 s. rustbgpd logged the signal release, not the deadline one, and `bgp_gr_eor_grace_released_total{reason="replay_complete"}` was 1 with `reason="deadline"` 0. In the same run the window-off control (phase 2) had End-of-RIB 244 ms before the replayed bans; four runs on this driver put it at 111-244 ms. A bridge built to signal before its reconcile pass fails this phase: End-of-RIB came 1 ms (IPv4) and 42 ms (IPv6) before the replay, a gap no 1 s poll would see. |

50 checks, 0 failed, on the head that adds this leg. The window phases were
added later. On 2026-10-20 the extended driver passed 75 checks with 0
failed: the control gap opened 1 s after the start, with no withdrawal, and
the bans returned at 13 s. A re-run with the bridge's liveness probe passed
76 checks: FRR's log showed both replayed bans before End-of-RIB in phase 5
(gap 0 ms), against 409 ms in the control. With the daemon reporting its
process incarnation, a later run passed 77 checks, with both bans fresh 2 s
after the start in phase 5. With phase 7 added, the driver passed 92 checks
with 0 failed on 2026-10-21; the run above is on the final driver, which
reads each replayed prefix's own line in FRR's log because FRR omits a
repeated attribute line. Every ban, unban and
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
- FastNetMon 1.2.9 does not keep an IPv6 ban for the whole attack. It logs
  `Sorry, we do not support unban_only_if_attack_finished for IPv6`, lifts the
  IPv6 ban after `ban_time` while the attack continues, and bans it again on
  the next detection. IPv4 bans honour `unban_only_if_attack_finished`. The
  window phases therefore count a ban missing at FRR as a gap only when FRR
  logged no withdrawal for it. Duplicate bans and unbans are covered by the
  bridge's own integration test, not this leg.
- Phases 5 and 6 show the observed gap closed when the bridge replays inside
  the window. A timer does not prove that replay completed, and a 1 s poll
  could miss a shorter gap. Phase 7 closes the gap when the listed controller
  signals before the deadline: the release follows the bridge's completed
  replay, and the order is read from FRR's millisecond log rather than from
  polls. The signal covers the bans the bridge tracks, not FastNetMon's own
  view, and one run on this two-ban shape is not a scale or timing bound.
- Not in CI: the leg downloads a 95 MB vendor package and runs for about
  seven minutes.
