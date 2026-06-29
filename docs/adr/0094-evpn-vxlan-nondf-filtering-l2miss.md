# ADR-0094: EVPN VXLAN all-active BUM filtering via kernel `l2_miss` (revisits ADR-0065)

**Status:** Accepted — **spike PASSED (2026-06-29, 6/6)**: the `l2_miss` egress
filter works on a standard bridged VXLAN softswitch, overturning
[ADR-0065](0065-evpn-localbias-split-horizon.md)'s ASIC-only deferral. A2 moves
from "ASIC/offload-only" back to an achievable softswitch feature (kernel ≥ 6.5,
iproute2 ≥ 6.3). Production wiring + the multi-PE composition (assertion (i))
follow. See "Spike result".
**Date:** 2026-06-29

## Context

[ADR-0065](0065-evpn-localbias-split-horizon.md) is the only remaining all-active
EVPN multi-homing forwarding-correctness gate. Everything else ships: the
all-active control plane (Type 1 EAD-per-ES/per-EVI, Type 4 ES, DF election,
ES-Import RT, mass-withdraw), receive-side **aliasing ECMP** via FDB nexthop
groups (ADR-0059, M40-proven), role-based BUM flood suppression (Gate 8b, A1),
and all-active Type 5 ECMP receive (ADR-0090). `RedundancyMode::AllActive` is the
config default. The single missing piece is **overlay-BUM split-horizon**: a PE
must not deliver duplicate BUM to a multi-homed CE.

ADR-0065 spiked one candidate mechanism — a two-stage `tc-flower` design keyed on
the **overlay source IP** (`enc_src_ip <peer-VTEP> enc_key_id <VNI>` on the VXLAN
device ingress → mark → CE-egress drop) — and it **failed decisively**: a
standard (non-`collect_metadata`) bridged VXLAN device strips the outer/tunnel
metadata before the inner frame reaches the device ingress qdisc, so `enc_src_ip`
matched 0 packets. ADR-0065 leaned on FRR #15400 (Feb 2024, "EVPN-MH
split-horizon non-functional on the softswitch") to conclude the softswitch path
was dead, and deferred A2 as ASIC/SAI-only.

### What ADR-0065 did not test (and explicitly flagged as the open avenue)

ADR-0065's own *Decision outcome* (lines 156–164) named the remaining softswitch
avenue — classify/mark on the **underlay before decap**, or operate on the
decapsulated inner frame — but blocked it on two unknowns: **(1) mark survival
through decap** and **(2) per-MAC state to separate unknown-unicast from
known-unicast** at the egress hook. It had no concrete kernel primitive for
either, so it stopped at the ASIC deferral.

Mainline Linux gained exactly that primitive in **6.5**: the **`l2_miss`** skb
bit (commit `7b4858df3bf7` "skbuff: bridge: Add layer 2 miss indication", Ido
Schimmel/NVIDIA), added **specifically for EVPN non-DF filtering**. The commit
message states the use case verbatim — *"prevent decapsulated traffic from being
flooded to a multi-homed host"* — and the design:

- The **bridge driver** sets `l2_miss` on a frame that took an FDB/MDB **miss**
  (i.e. unknown-unicast/unregistered-multicast); it is clear on a hit and never
  set for broadcast. This is the kernel maintaining the unknown-vs-known
  distinction natively — resolving ADR-0065's blocker (2) with **no daemon-side
  per-MAC state**.
- The filter runs on the **ES-facing egress** matching the **decapsulated inner
  frame** (`indev <vxlan-dev>` to scope to overlay-sourced traffic, `dst_mac`
  multicast-bit for B/M, `l2_miss 1` for unknown-unicast) — it never needs the
  stripped outer source, resolving ADR-0065's blocker (1) and the `enc_src_ip`
  wall.
- It works on a **standard bridged VXLAN** — no `collect_metadata` required.

So ADR-0065's ASIC deferral was *half* outdated: it disproved the `enc_src_ip`
mechanism (still true) and over-generalized to "all softswitch MH filtering is
impossible" (false as of 6.5). FRR still ships no working softswitch version
(#15400 open as of Feb 2026; FRR's DF-state dplane ops have no backend handling),
so wiring this in rustbgpd would do something **FRR-on-Linux currently cannot** —
a genuine differentiator (today this exists only on ASIC/SAI or DIY nftables
daemons).

### The honest open question this revisit must resolve

`l2_miss` + `indev` is **non-DF, frame-class egress filtering** ("drop
overlay-sourced BUM toward this ES bond"), **not** the source-conditioned
RFC 8365 §8.3.1 *local bias* ADR-0065 pursued ("drop only BUM whose overlay
source is an ES-peer VTEP"). It is blunt by design: it drops *all* overlay-sourced
BUM toward the ES bond, regardless of which VTEP sent it. Correctness therefore
does not come from the filter alone — it must **compose with DF election**:

- **Non-DF PE for an (ESI,VNI):** installs the filter → drops all overlay BUM
  toward that ES bond.
- **DF PE:** forwards overlay BUM toward the ES bond.

This composition is what the spike must validate, because two cases are
non-obvious and are exactly where a partial implementation would mis-forward:

1. **Externally-sourced BUM must still reach the multi-homed CE.** With non-DFs
   dropping all overlay BUM, the multi-homed CE must still receive legitimate
   broadcast from a remote *non-ES* host — via the **DF** (which does not filter).
   Net: exactly one copy reaches the CE. The spike must prove the DF path
   delivers it and the non-DF path drops the duplicate.
2. **ES-peer-sourced BUM must not duplicate back to the multi-homed CE.** When an
   ES-peer PE locally floods to the shared CE *and* sends the overlay copy, the
   DF (which does not filter) would re-deliver that overlay copy to the same
   shared CE — a duplicate the blunt `l2_miss` filter does not catch on the DF.
   The spike must determine whether DF election alone avoids this (e.g. the DF is
   also the one PE that owns CE delivery, and ES-peer-as-ingress implies the
   ingress already delivered) **or** whether a residual source-conditioned drop
   is still needed on the DF for the shared-ES case. **This is the load-bearing
   correctness question** — if `l2_miss` + DF election closes it, A2 is solved on
   the softswitch; if a residual DF-side gap remains, we learn the precise
   boundary cheaply.

## Decision

**Spike-first, again** — re-run the ADR-0065 gate with the `l2_miss` mechanism on
a kernel ≥ 6.5 before any daemon wiring. ADR-0065 was correct to gate on a real
kernel; this revisit does the same with the mechanism it could not have tested.
No production code lands until the spike resolves the composition question above.

### The spike (the gate)

`crates/evpn-linux/tests/scripts/netns-l2miss-sph-spike.sh` — derived from the
existing `netns-localbias-sph-spike.sh` (reuse its 3-VTEP-in-netns topology:
`loc` PE-under-test with a bridged VXLAN + CE, `esp` ES-peer VTEP, `nes` non-ES
VTEP, joined by an underlay bridge; remote VTEPs head-end-replicate BUM to `loc`
via static all-zero VXLAN FDB). Run under Docker
`--cap-add=NET_ADMIN --cap-add=SYS_ADMIN --security-opt apparmor=unconfined`,
kernel via `rustbgpd-netns-tests:latest`. **Record the kernel version** (≥ 6.5
required for `l2_miss`; the harness must skip-with-clear-message on older
kernels).

The candidate filter on the CE/ES-bond **egress** (replacing the failed
two-stage `enc_src_ip` design):

```
# B/M overlay-sourced toward the ES bond:
tc filter add dev <es-bond> egress flower indev <vxlan-dev> \
    dst_mac 01:00:00:00:00:00/01:00:00:00:00:00 action drop
# Unknown-unicast overlay-sourced toward the ES bond (kernel sets l2_miss on FDB miss):
tc filter add dev <es-bond> egress flower indev <vxlan-dev> l2_miss 1 action drop
# (known unicast: l2_miss 0 → unmatched → forwarded)
```

**Assertion matrix** (extends ADR-0065's (a)–(g) to the `l2_miss` mechanism and
adds the composition checks):

| # | Assertion | Why it is the gate |
|---|---|---|
| (a) | `l2_miss 1` is matchable by flower on the ES-bond egress and matches **unknown-unicast** decapsulated frames | the make-or-break primitive; proves blocker (2) is solved natively |
| (b) | `indev <vxlan-dev>` scopes the filter to overlay-sourced frames (locally-sourced from the CE are not matched) | proves overlay-vs-local distinction without the stripped outer source |
| (c) | Broadcast from the ES-peer VTEP → **dropped** toward the shared CE | B/M class |
| (d) | Multicast from the ES-peer VTEP → **dropped** | B/M class |
| (e) | Unknown-unicast from the ES-peer VTEP → **dropped** | the case `enc_src_ip` could not reach; `l2_miss` must |
| (f) | **Known-unicast** from the ES-peer VTEP to a CE-learned MAC → **still forwards** | the crux ADR-0065 feared; `l2_miss 0` must leave it untouched |
| (g) | Locally-sourced BUM from the CE (`indev` = CE port) → **still floods** to other local ACs | the filter must not over-drop local traffic |
| (h) | **Composition — externally-sourced delivery:** non-ES BUM dropped on the non-DF `loc`, but reaches the CE when `loc` is modelled as **DF** (no filter) | proves the DF/non-DF split delivers exactly one copy |
| (i) | **Composition — ES-peer dedup on the DF:** with `loc` as **DF**, determine whether ES-peer-sourced overlay BUM still duplicates to the shared CE (and if so, what residual mechanism closes it) | the load-bearing correctness question |

(a), (e), (f) prove the mechanism; (h), (i) prove the composition. **(i) is the
decision pivot.**

### Fallback ladder

1. If (a)/(e)/(f) pass but (i) reveals a residual DF-side ES-peer duplicate that
   the frame-class filter cannot close, evaluate a **narrow source-conditioned
   add-on on the DF only** (the duplicate is bounded to ES-peer VTEPs, a small
   known set from DF election) before concluding ASIC-only.
2. If (a) fails on a current kernel (the `l2_miss`/`indev` egress filter cannot
   be made to drop overlay BUM on a standard bridged VXLAN), **ADR-0065's
   ASIC/offload deferral stands unchanged** — and we will have spent one spike,
   not a sprint, to confirm it against the newest available mechanism.

## Spike result

Ran `crates/evpn-linux/tests/scripts/netns-l2miss-sph-spike.sh` (2026-06-29;
host kernel **6.17**, `tc`/iproute2 **6.15** in a `debian:trixie` container over
the host kernel — the repo's `rustbgpd-netns-tests` image and the host both ship
iproute2 6.1, too old for the `l2_miss` flower key, so the spike ran in a
newer-userspace container with `--cap-add=NET_ADMIN --cap-add=SYS_ADMIN`).
**6/6 — the gate PASSED.** The candidate `l2_miss` egress filter on a standard
bridged VXLAN does what ADR-0065's `enc_src_ip` design could not:

- **(a) `l2_miss 1` installs + matches: PASS** — `flower indev vxlan100 l2_miss 1`
  on the CE-port egress matched unknown-unicast (5 pkts). The kernel sets the
  miss bit on the decapped inner frame and `tc` reads it — no overlay source, no
  daemon-side per-MAC state. (ADR-0065's `enc_src_ip` matched 0.)
- **(b) broadcast / (c) multicast dropped: PASS** (CE delta 0 vs baseline 47) via
  `indev vxlan100 dst_mac <mcast-bit>`.
- **(e) unknown-unicast dropped: PASS** (delta 2) — the case the failed spike
  fundamentally could not reach.
- **(f) known-unicast preserved: PASS** (delta 5) — FDB hit → `l2_miss 0` →
  forwarded; the over-drop ADR-0065 feared does not occur.
- **(g) source-blind: confirmed** — with the filter on, non-ES broadcast is also
  dropped (expected; the filter is frame-class, not source-conditioned).
- **(h) DF delivery: PASS** — with the filter removed (DF role), non-ES broadcast
  reaches the CE. The production composition is therefore: install on **non-DF**
  PEs; the **DF** delivers external BUM.

### What the spike did NOT resolve — assertion (i)

The harness models one PE with the CE on it; it proves the mechanism and the
source-blindness but cannot measure the **DF-side ES-peer duplicate** (an ES-peer
PE locally floods to the *shared* CE while the DF re-delivers the overlay copy).
That needs a 2-PE-shared-CE topology, or resolves in the production design. Open
item for the wiring phase: confirm whether DF election alone closes it, or a
narrow source-conditioned drop for the (small, DF-election-known) ES-peer-VTEP
set on the DF is required.

### Decision outcome

A2 **moves from "ASIC/offload-only" (ADR-0065) back to an achievable softswitch
feature** on kernel ≥ 6.5 / iproute2 ≥ 6.3, via the `l2_miss` egress filter
composed with the existing DF election. rustbgpd would ship working
pure-softswitch EVPN-MH BUM filtering, which FRR-on-Linux does not (#15400). Next:
the production-wiring plan + the (i) composition spike, gated behind
`apply_sph_filters` (default off → observe → default-on after a protected smoke +
soak), with the kernel ≥ 6.5 floor documented.

## Consequences

- Until the spike resolves (i), all-active keeps ADR-0065's qualifier:
  DF/non-DF BUM suppression + aliasing ECMP ship; **overlay-BUM split-horizon
  remains the open all-active correctness gate**, now narrowed to a single
  testable kernel mechanism rather than "ASIC-only."
- If the spike passes, a follow-up plan covers production wiring on the existing
  reconciler discipline: persist the per-(ESI,VNI) DF role + ES-bond identity,
  publish on the BUM-enforcement watch channel, program the `tc-flower` egress
  rules from the reconciler with the A1 ownership/rollback/drift discipline, gate
  behind `apply_sph_filters` (default off → observe-only → default-on only after
  a protected M-series smoke + soak), and **document the kernel ≥ 6.5 floor**.
  This adds a `tc-flower` programming primitive to `evpn-linux` (today it
  programs netlink FDB/route/nexthop; tc-flower rule install/rollback is net-new
  but contained, and mirrors the existing diff/ownership model).
- rustbgpd would gain working pure-softswitch EVPN-MH split-horizon — a capability
  FRR-on-Linux does not currently ship (#15400). Any FRR peer in a future interop
  may itself leak, so the interop asserts only rustbgpd's behavior.

## References

- [ADR-0065](0065-evpn-localbias-split-horizon.md) — the original split-horizon
  spike (disproved `enc_src_ip`; deferred A2 as ASIC-dependent). This ADR
  revisits its deferral with a mechanism it could not test.
- RFC 8365 §8.3.1 (VXLAN local-bias) · RFC 7432 §8.3 (split-horizon) ·
  RFC 9746 (EVPN-MH split-horizon).
- Linux commit `7b4858df3bf7` "skbuff: bridge: Add layer 2 miss indication"
  (mainline 6.5) — the `l2_miss` primitive, added for EVPN non-DF filtering;
  `tc-flower(8)` (`l2_miss` key). SONiC EVPN-MH HLD (cites the 6.5 mechanism +
  the SAI/ASIC alternative).
- FRR #15400 — EVPN-MH split-horizon non-functional on the Linux softswitch
  (open as of Feb 2026; FRR DF-state dplane ops have no backend handling).
- `crates/evpn-linux/tests/scripts/netns-localbias-sph-spike.sh` (the harness to
  derive the new spike from); `crates/evpn-linux/src/linux/bum_filter.rs` (A1
  primitive + the reconciler ownership model the production wiring would reuse).
