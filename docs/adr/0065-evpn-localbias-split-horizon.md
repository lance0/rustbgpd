# ADR-0065: EVPN VXLAN local-bias split-horizon (spike-gated)

**Status:** Accepted — spike disproved the softswitch mechanism; A2 deferred as
ASIC/offload-dependent (documented limitation). See "Spike result".
**Date:** 2026-05-22

## Context

EVPN all-active multi-homing has a forwarding-correctness requirement that
rustbgpd does not yet meet on the Linux softswitch: **local-bias split-horizon**
(RFC 8365 §8.3.1). When a PE receives BUM (broadcast / unknown-unicast /
multicast) over VXLAN from a peer NVE that *shares the same Ethernet Segment*,
it must NOT forward that BUM back onto the local CE-facing interface of that
shared segment — the ingress PE already locally-flooded it to the shared CE
("local bias"). Without this, all-active CE hosts see duplicate BUM and, with
the wrong topology, loops.

This is distinct from what already ships:

- **A1 (shipped, ADR-0057 + Gate 8b):** per-CE-port BUM flood suppression keyed
  on the DF/non-DF *role*. The reconciler programs the bridge-port flood-flag
  triplet `IFLA_BRPORT_{UNICAST,MCAST,BCAST}_FLOOD`
  (`crates/evpn-linux/src/linux/bum_filter.rs`). This is **port-wide and
  source-blind** — a non-DF CE port suppresses all BUM regardless of which NVE
  it came from.
- **A2 (this ADR):** **overlay-source-conditioned** filtering — the DF still
  floods legitimate (externally-sourced) BUM and still forwards known unicast,
  but drops BUM whose VXLAN ingress source is a peer-VTEP sharing the ESI. A1's
  flood-flag primitive cannot express this; A2 is net-new.

ADR-0057 explicitly deferred split-horizon enforcement, noting the Linux
dataplane "doesn't currently program ESI-label-aware filters."

### Why this is a spike, not a straight implementation

Investigation of the wider ecosystem found that **mainline Linux has no native
source-conditioned EVPN-MH split-horizon on the softswitch dataplane.** FRR and
Cumulus implement it as userspace-driven `tc` filters on the VXLAN device, and
FRR's pure-Linux-softswitch split-horizon is reported **non-functional**
(FRR issue #15400, Feb 2024); the feature is reliable only on ASIC dataplanes
via SAI (`SAI_BRIDGE_PORT_ATTR_TUNNEL_TERM_BUM_TX_DROP` + isolation groups, per
the SONiC EVPN-MH HLD). The bridge `IFLA_BRPORT_ISOLATED` flag is port-pairwise,
not overlay-source-conditioned, so it cannot express "drop only BUM whose
overlay source is an ES-peer VTEP."

The candidate mechanism is therefore a two-stage `tc` design:

1. `tc-flower` on the **VXLAN device ingress** matching
   `enc_src_ip <peer-VTEP> enc_key_id <VNI>` → `skbedit` a reserved fwmark.
2. The **CE-port egress** drops marked frames.

Two unknowns make this make-or-break, and are exactly why we spike before
wiring any daemon code:

1. **Mark survival.** The fwmark set at VXLAN ingress must survive VXLAN decap +
   bridge forwarding to the CE-port egress hook. If it doesn't, the two-stage
   design is dead even if `enc_src_ip` matching works. (Linux VXLAN tunnel
   metadata is generally only attached in `external` / `collect_metadata` mode;
   rustbgpd uses normal operator-provisioned VXLAN devices today.)
2. **Unknown-unicast vs known-unicast at egress.** Broadcast/multicast are easy
   (inner dMAC class is obvious to flower). Unknown unicast is the crux: at the
   CE egress hook a flooded-unknown-unicast frame and an FDB-forwarded
   known-unicast frame both look like ordinary unicast Ethernet. A blunt
   source-mark + egress-drop risks over-dropping legitimate known unicast or
   under-filtering unknown unicast. Local-bias must drop B/U-U/M from the ES
   peer while **preserving known unicast** to CE-local MACs.

## Decision

Spike-first. Land an exploratory netns spike that proves (or disproves) the
mechanism against a real kernel before any daemon wiring. The spike is the gate.

### Spike (the gate)

`crates/evpn-linux/tests/scripts/netns-localbias-sph-spike.sh` — a standalone
privileged netns spike (run under Docker `--cap-add=NET_ADMIN --cap-add=SYS_ADMIN
--security-opt apparmor=unconfined`, mirroring the Gate 8b bum-filter spike). It
stands up a local VTEP (VXLAN device bridged with a CE veth) plus two remote
VTEPs on a shared underlay — one standing in for an **ES-peer** VTEP, one for a
**non-ES** VTEP — and asserts, each traffic class independently:

- (a) **Mark survival** — a mark set by flower at VXLAN ingress is observable at
  the CE-port egress hook.
- (b) **`enc_src_ip` match** — flower on VXLAN ingress matches the overlay
  source IP + VNI.
- (c) **Broadcast** from the ES-peer VTEP → dropped to the shared CE.
- (d) **Multicast** from the ES-peer VTEP → dropped to the shared CE.
- (e) **Unknown unicast** from the ES-peer VTEP → dropped to the shared CE.
- (f) **Known unicast** from the ES-peer VTEP to a CE-learned MAC → still
  forwards.
- (g) **Negative control** — BUM from the non-ES VTEP → still reaches the CE
  (proves true local-bias, not a blunt "drop all VXLAN BUM to CE").

(a), (e), and (f) decide whether the two-stage tc-flower design is viable.

### Fallback ladder (recorded so the spike outcome has a defined next step)

If `tc-flower` cannot satisfy (a)/(e)/(f) on the softswitch, the fallback is
**not** "use eBPF" generically:

1. An eBPF `tc` program with enough state to recognize known local CE MACs, so
   it can drop unknown-unicast from an ES-peer without touching known unicast.
2. Failing that, a **documented pure-Linux limitation** — A2 is achievable only
   on an ASIC/offload dataplane (matching FRR #15400), and rustbgpd records the
   gap honestly rather than shipping a partial filter that mis-handles known
   unicast.

## Consequences

- Until the spike resolves the mechanism, all-active multi-homing keeps the
  documented qualifier: **production-default DF/non-DF BUM suppression and
  aliasing ECMP ship; VXLAN local-bias split-horizon remains the remaining
  all-active correctness gate.** Docs are updated to stop implying full
  multi-homing enforcement.
- If the spike passes, a follow-up ADR/plan covers the production wiring:
  persist the per-ESI peer-VTEP set after DF election, publish it on the
  existing BUM-enforcement watch channel, program the filter from the reconciler
  with the A1 ownership/rollback/drift discipline, gate it behind
  `apply_sph_filters` (default off → observe-only first → default-on only after
  an M46 protected smoke + soak).
- The spike asserts only rustbgpd's behavior; FRR's own softswitch SPH is broken
  (#15400), so an FRR peer in any future interop may itself leak.

## Spike result

Ran `netns-localbias-sph-spike.sh` (2026-05-22, Docker `--cap-add=NET_ADMIN
--cap-add=SYS_ADMIN`, kernel via `rustbgpd-netns-tests:latest`). **The gate
failed decisively — the candidate stateless tc-flower design is not viable on
the standard bridged-VXLAN softswitch:**

- **(b) `enc_src_ip` match: FAIL.** The filter installs (the kernel accepts
  `flower enc_src_ip … enc_key_id …` on the VXLAN device ingress) but matches
  **0 packets**, even though the same ES-peer broadcast demonstrably floods to
  the CE port (flood baseline = 43 frames).
- **Isolation diagnostic:** a `matchall` filter on the same `vxlan100 ingress`
  hook matched **11 packets**. So the hook *does* see the decapped inner frame —
  only the `enc_*` tunnel metadata (overlay source IP) is missing. A normal
  (non-`collect_metadata`) VXLAN device strips the outer/tunnel info before the
  inner frame reaches the device's ingress qdisc.
- **(a) mark survival: FAIL** (skipped — no mark is ever set because (b) fails).
- **(c)/(d)/(e) drops: FAIL** — consequences of (b): BUM floods to CE normally.
- **(f) known-unicast preserved / (g) non-ES BUM reaches CE: PASS** — trivially,
  since no source-conditioned filter is ever active.

This reproduces the FRR #15400 failure mode exactly: on the standard bridged
VXLAN dataplane the overlay source is not available to `tc` at the point where
split-horizon would need it.

### Decision outcome

**A2 (VXLAN local-bias split-horizon) is deferred as an ASIC/offload-dependent
feature on the standard softswitch VXLAN model**, matching the wider ecosystem
(FRR softswitch SPH is non-functional; SONiC does it in the ASIC via SAI). The
sprint pivots to #210 (Gate D) per the plan.

The only remaining *softswitch* avenue (unproven, materially heavier, out of
this sprint) is **not** the planned vxlan-ingress flower: it would be a tc/eBPF
program on the **underlay** interface ingress — where the full encapsulated
packet (outer src IP + VNI + inner dMAC) is still visible — classifying and
marking *before* decap, then dropping marked frames on CE egress. That path
still has to clear the mark-survival-through-decap unknown and needs per-MAC
state to separate unknown-unicast from known-unicast; or it requires switching
operators to `collect_metadata`/external VXLAN, a separate dataplane
re-architecture. Either is its own ADR if demand appears.

## References

- RFC 8365 §8.3.1 (VXLAN local-bias) · RFC 7432 §8.3 (split-horizon).
- ADR-0057 (Gate 8 DF election; split-horizon deferral).
- FRR #15400 — EVPN-MH split-horizon filters not functional on the Linux
  softswitch.
- SONiC EVPN VXLAN Multihoming HLD (ASIC/SAI BUM-TX-drop + isolation groups).
- `crates/evpn-linux/src/linux/bum_filter.rs` (A1 primitive);
  `crates/evpn-linux/tests/scripts/netns-bum-filter-spike.sh` (spike model).
