# M123: RFC 9785 Don't-Preempt against SR Linux 25.10.1

This run qualifies RFC 9785 Highest-Preference Don't-Preempt (DP) recovery
between rustbgpd and Nokia SR Linux 25.10.1-399 on one all-active Ethernet
Segment, with a Linux CE that bundles both PE links into one LACP aggregator.

The run passed on 2026-10-13, 13:35:05–13:37:25 UTC: **20 passed, 0 failed**,
11 phases, and an offline replay of every phase. The lab was destroyed
afterwards. The same driver runs as the hosted M123 job in
[`kernel-dataplane.yml`](../../../../.github/workflows/kernel-dataplane.yml).
This is a two-PE control-plane qualification without traffic. EVPN remains alpha.

## Identity and evidence

[Provenance](provenance.json) records daemon source
`2ebe2e58fce2e12f5e618f3b262d90268425a6e1`, the image source-ID check, image
IDs, binary hashes and harness hashes. The SR Linux image is pinned by digest;
the runner verifies the deployed image ID and the
[reported version and build](srl-version.txt).

Each phase directory holds the raw observations and the oracle's reduction:

- `rust-es.json`: `rbgp evpn es list -j`, with administrative and advertised
  preference/DP, recovery state and per-VNI DF role.
- `rust-type4.json`: `rbgp evpn --route-type 4 -j` (ListEvpnRoutes), with raw
  extended communities for rustbgpd's own Type 4 and SR Linux's.
- `srl-es.json`: SR Linux ES state, with `preference-value`,
  `oper-preference-value`, `oper-do-not-prempt`, the computed DF candidates
  and `designated-forwarder-role-last-change`.
- `srl-rib.json`: SR Linux BGP RIB, whose attribute sets carry SR Linux's own
  decode of each DF Election extended community.
- `ce-bond.txt`: the CE's `/proc/net/bonding/bond0`.
- `facts.json` and `expect.json`: what
  [the oracle](../../../../tests/interop/scripts/m123_dont_preempt_oracle.py)
  extracted, and what the phase required.

The [run log](run.log) and the [daemon log](rustbgpd.log) are retained. The
daemon log's `DF role updated` lines show rustbgpd's role history: `nondf`
through both DP restarts, `df` only in the DP-off control and after SR Linux
withdrew, and `nondf` again after it was undrained below SR Linux.

## Topology

[Topology](../../../../tests/interop/m123-evpn-dont-preempt-srlinux.clab.yml),
[rustbgpd config](../../../../tests/interop/configs/rustbgpd-m123-pe.toml),
[SR Linux config](../../../../tests/interop/configs/srl-m123-dont-preempt.cli).
The PEs peer over iBGP L2VPN/EVPN on `10.0.123.0/24`. rustbgpd originates
from `10.0.123.1` and SR Linux from its system address `192.0.2.2`, so
rustbgpd wins an IP tie-break and only DP can keep SR Linux DF at equal
preference. ESI `00:01:23:00:00:00:00:00:00:01` is all-active on VNI 100,
with Highest-Preference and DP on both sides. rustbgpd's administrative
preference is 200, SR Linux's is 100. The rustbgpd bond and SR Linux's `lag1`
use the same LACP system ID (`00:00:00:00:01:23`), priority and key (15), so
the CE puts both links in one aggregator. Every phase with both links up
reports two collecting and distributing ports.

## Observed values

(pref, DP) pairs. "Own" is the Type 4 a PE originates; "decoded" is the other
PE's Type 4 as this PE decodes it.

| Phase | rustbgpd admin / advertised | rustbgpd own Type 4 | SR Linux admin / oper | SR Linux decodes rustbgpd | DF |
|---|---|---|---|---|---|
| srl-alone | not running | — | (100, 1) / (100, 1) | — | SR Linux |
| dp-boot | (200, 1) / (100, 0) | (100, 0) | (100, 1) / (100, 1) | (100, 0) | SR Linux, stamp unchanged |
| dp-restart | (200, 1) / (100, 0) | (100, 0) | (100, 1) / (100, 1) | (100, 0) | SR Linux, stamp unchanged |
| control-preempt | (200, 0) / (200, 0) | (200, 0) | (100, 0) / (100, 0) | (200, 0) | rustbgpd |
| dp-restored | (200, 1) / (100, 0) | (100, 0) | (100, 1) / (100, 1) | (100, 0) | SR Linux, stamp unchanged |
| srl-withdrawn | (200, 1) / (200, 1) | (200, 1) | ES down, CE link down | (200, 1) | rustbgpd |
| srl-recovered | (200, 1) / (200, 1) | (200, 1) | (300, 1) / (200, 0) | (200, 1) | rustbgpd, stamp unchanged |
| rust-drained | drained | withdrawn | (300, 1) / (300, 1) | — | SR Linux |
| rust-undrained | (200, 1) / (200, 1) | (200, 1) | (300, 1) / (300, 1) | (200, 1) | SR Linux, stamp unchanged |

rustbgpd's raw DF Election communities: `06:06:02:00:00:00:00:64` while
inheriting (Highest-Preference, bitmap 0, preference 100) and
`06:06:02:80:00:00:00:c8` as reference (DP set, preference 200). SR Linux
advertises `06:06:02:c0:00:00:00:64` (DP and AC-DF set, preference 100) and,
while inheriting, `06:06:02:40:00:00:00:c8` (AC-DF only, preference 200). Its
RIB renders rustbgpd's routes as, for example,
`df-election::DF-Type:Preference/DP:0/DF-Preference:100/AC:0`. rustbgpd does
not set AC-DF; neither side fell back to modulo.

## What each cell shows

- **Restart (dp-boot, dp-restart, dp-restored).** Once SR Linux is the only
  DF, rustbgpd is started, then restarted with SIGTERM, then started again
  after the control cell. Each time the daemon log records SR Linux's EVPN
  End-of-RIB before rustbgpd's first DF role; rustbgpd advertises SR Linux's
  preference with DP=0 and stays non-DF. SR Linux's
  role-change stamp equals the one taken before rustbgpd started, to within
  a second.
- **Control (control-preempt).** With DP off on both sides, the same restart
  makes rustbgpd DF with (200, DP=0).
- **Drain of SR Linux (srl-withdrawn).** SR Linux's CE port is disabled, so
  its ES goes down and its Type 4 is withdrawn. The surviving rustbgpd
  restores (200, DP=1) and becomes DF. The CE bundle drops to one port.
- **Reverse (srl-recovered).** SR Linux's administrative preference is raised
  to 300 while its link is down, then the link is restored. SR Linux reports
  `oper-preference-value` 200 and `oper-do-not-prempt` false, advertises
  (200, DP=0), and rustbgpd stays DF.
- **Drain of rustbgpd (rust-drained, rust-undrained).** `rbgp evpn es drain`
  withdraws rustbgpd's Type 4; SR Linux restores (300, DP=1) and becomes DF.
  After `undrain`, rustbgpd recovers below the reference and keeps its
  administrative (200, DP=1), as §4.3 specifies, and SR Linux stays DF.

## SR Linux behavior observed

- SR Linux runs the non-revertive procedure when its ES recovers from an
  attachment-link failure. In an exploratory run, raising a disabled ES to
  preference 300 and re-enabling it with `admin-state enable` made SR Linux
  advertise (300, DP=1) and preempt rustbgpd. RFC 9785 §4.3 covers failure
  recovery, not administrative changes.
- In an exploratory run, a warm `tools system app-management application
  evpn_mgr restart` made SR Linux re-advertise its administrative (300, DP=1)
  and take DF from rustbgpd, which held it with (200, DP=1). The leg does not
  assert this.
- `tools platform chassis reboot` stops the container, and containerlab does
  not restore its links. So this receipt has no SR Linux node-restart cell.
- `designated-forwarder-role-last-change` is rewritten about five seconds
  after a role change without a role change. It can also lag the candidate
  table, and an unchanged stamp re-renders a few milliseconds apart between
  reads. The oracle therefore waits for a stamp that postdates the action and
  is 15 seconds old, then accepts later reads within one second.

## Negative proof

With the inheritance assignment in `update_operational_df`
(`src/evpn_segment.rs`) removed locally, the same leg fails at dp-boot. The
oracle reported rustbgpd advertising and originating (200, DP=1), SR Linux
decoding (200, DP=1), rustbgpd DF and SR Linux non-DF, and SR Linux's
role-change stamp moved. That patch was not committed.

## Scope

Covered: Highest-Preference, two PEs, one ES and one VNI, rustbgpd restart
and boot, SR Linux attachment-link recovery, reference withdrawal by link
failure and by operator drain, and a DP-off control. Not covered:
Lowest-Preference, per-Ethernet-Tag policy (§4.2), more than two PEs, an SR
Linux node restart, graceful restart, forwarding or BUM handling, or
convergence time.
