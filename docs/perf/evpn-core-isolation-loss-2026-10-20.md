# EVPN core-isolation transition loss — 2026-10-20

This receipt bounds the traffic lost while a core-isolated all-active PE takes
its Ethernet Segment members down ([ADR-0140](../adr/0140-evpn-core-isolation-es-hold.md)).
The loss runs from the moment rustbgpd's underlay is cut until the CE moves
the flow to the other PE. With `[evpn_core_isolation]` enabled, the median
loss window was about 15 ms, and the worst of the 48 valid A/B cycles was 35.5 ms.
With the action disabled, every valid cycle lost the flow for the whole 8 s
post-cut window. Measured 2026-10-19 and 2026-10-20 on a quiet host.

| Arm | Build | Night | Valid cycles | Loss window ms, min / median / max | Frames lost, median (range) | Cut → last frame on rustbgpd member ms, median (range) |
|---|---|---|---|---|---|---|
| Action | `ac5a1b8d5` | 2026-10-20 | 24 / 24 | 4 / **15** / 35.5 | 30 (8–71) | 16.3 (5.1–36.6) |
| Action | `090022493` | 2026-10-20 | 24 / 24 | 14.5 / **15.5** / 30.5 | 31 (29–61) | 16.6 (15.3–31.7) |
| Action | `090022493` | 2026-10-19 | 10 / 12 | 14.0 / 17.75 / 28.5 | 35.5 (28–57) | 19.0 (15.2–29.7) |
| Control (action disabled) | `090022493` | 2026-10-19 | 11 / 12 | ≥8,029 / **≥8,030** / ≥8,030 | 16,060 (16,058–16,060) | 8,030.8 (8,030.1–8,031.3) |

All 11 valid control cycles are censored: the flow was still being lost when
the 8 s window ended, so ≥8,030 ms is a lower bound, not a measured window.

## Shape

- **Topology.** The M121 interop topology
  (`tests/interop/m121-evpn-all-active-frr.clab.yml`): rustbgpd and FRR 10.7.1
  share one all-active Ethernet Segment toward a Linux 802.3ad CE bond, and a
  remote FRR PE fronts the remote host. rustbgpd runs with
  `[evpn_core_isolation] enabled = true`, `uplinks = ["ul"]` and the ADR
  defaults (10 s settle hold, 180 s backstop). The control arm is the same
  configuration with `enabled = false`.
- **Probe.** One UDP flow from the CE to the remote host, which the CE bond
  (`layer3+4` hash) places on rustbgpd's member, at 2,000 frames/s (0.5 ms
  spacing). Each frame carries its sequence number and send time. Captures on
  both CE members give the sent set; a capture at the remote host gives the
  delivered set.
- **Cycle.** 2 s of steady traffic, then `ip link set ul-b down` on
  rustbgpd's underlay link, then 8 s more traffic. The loss window is the send
  time of the last lost frame minus that of the first, plus one interval.
- **Recovery (v2 harness).** After the EVPN sessions expire, the underlay is
  restored and both rustbgpd EVPN neighbors are reset administratively, in
  both arms. The reset clears the FSM's reconnect backoff, which otherwise
  doubles with every hold-timer teardown, so each cycle starts from the same
  state. Loss is measured before the reset.
- **Validity.** A cycle is invalid if tcpdump drops frames, any sent frame is
  missing from the member captures, a frame is lost before the cut, the flow
  is not on rustbgpd's member before the cut, or the sender stalls for more
  than 10 ms.
- **Design.** 2026-10-19: one deployment, each arm in fresh namespaces with
  12 cycles, image
  `rustbgpd:qq1019-m121-090022493`. 2026-10-20: action arm only, 12 fresh
  deployments of 4 cycles each in ABBA ABBA ABBA order across
  `rustbgpd:qq1014-m121-ac5a1b8d5` (`57b4f31230fd`) and
  `rustbgpd:qq1019-m121-090022493` (`27bc32642a6a`). A block counted only if
  the controller's source id matched its image. Both images use the same
  harness; the M121 harness files do not differ between the two commits.
- **Host.** One AMD Ryzen Threadripper 7970X Linux host, kernel
  7.0.0-30-generic, containerlab 0.74.3, FRR image digest `e995beaa50fd`.
  Both nights ran in a quiet window with no other builds or labs; load
  average was about 1.3–1.5 on 2026-10-20.

## Bars

- The control arm must show the loss the action exists to prevent: the
  rustbgpd-hashed flow is lost for the whole post-cut window. **Met** (11 of
  11 valid cycles censored at the window end).
- The action arm must bound that loss to a finite window ending with the
  flow on FRR's member, in every valid cycle, with no censored cycle. **Met**
  (58 of 58 valid action cycles across both nights, 0 censored).
- The bound is accepted only if a same-night A/B shows no change between the
  two builds. **Met**: medians 15 and 15.5 ms with overlapping ranges.

## Results

- **Per position.** The first cycle of each 2026-10-20 block, which follows
  no reset, had a median loss window of 14.5 ms (`ac5a1b8d5`) and 14.75 ms
  (`090022493`); later cycles 15.25 and 15.75 ms. The v2 reset does not carry
  state into the next cut.
- **Invalid cycles.** 2026-10-19 action cycles 4 and 6 each had one sent frame
  missing from the member captures; control cycle 3 had a 2.9 s sender stall.
  None were excluded on 2026-10-20.
- **Recovery.** Neighbor reset to steady state took 11.9–16.1 s in the action
  arm (the 10 s settle hold applies) and 1.1–2.0 s in the control arm.

## Scope

- One lab topology on one host, one flow at one probe rate, veth links in
  network namespaces. This is not a hardware NIC, ASIC or line-rate claim.
- The cut is an uplink carrier loss, so the configured-uplink signal fired
  first. Isolation detected only by EVPN session loss, with no uplinks
  configured, waits for the BGP hold timer and was not measured.
- An earlier 2026-10-14 run under the v1 harness (n=5, no control arm)
  measured 4–5 ms windows. That run differs from these in the harness and
  environment; the same-night A/B rules out a change between the two builds,
  and the `ac5a1b8d5` image still produced a 4 ms cycle. The difference is
  not chased further. Under the v2 harness the bound is about 15 ms typical.

## Evidence

[`artifacts/evpn-core-isolation-loss-2026-10-20/`](artifacts/evpn-core-isolation-loss-2026-10-20/README.md)
holds the per-image A/B summary, the block log, the 2026-10-19 two-arm summary
and the harness patch.
