# Receipts Index

rustbgpd's development rule is simple: **every wire-behavior claim has a lab
that proves it, and every performance claim has a measured receipt.** A
feature is not "done" when the code merges — it is done when a containerlab
topology against a real peer implementation (FRR, BIRD, GoBGP), a real kernel
dataplane, or a documented same-host measurement demonstrates the claimed
behavior, and that evidence is checked in. This page is the single index of
those receipts: the M-series interop labs, the performance and scale
measurements, the archived long-running soaks, and the CI schedules that keep
re-proving all of it. The operator-facing roll-up (what has been proved, in
prose) is [`OPERATIONAL_PROOF.md`](OPERATIONAL_PROOF.md); detailed procedures
and per-test assertions live in [`INTEROP.md`](INTEROP.md). Receipts must
satisfy the [M-series proof quality
contract](INTEROP.md#m-series-proof-quality-contract): target-scoped
assertions, kernel evidence for kernel claims, rerunnable cleanup-safe
drivers, and a non-vacuity sentinel.

Numbering note: M0–M4 and M10 onward are interop labs. M5–M9 were
development-phase build milestones (wire/RIB/API hardening) and are documented
in [`milestones.md`](milestones.md), not here.

## Receipts → deployment recipes

Several receipt clusters back a copy-paste deployment recipe in
[`cookbook/`](cookbook/README.md) — the receipt proves the behavior,
the recipe is the config + runbook it enables:

| Receipts | Recipe |
|----------|--------|
| M14, M76, M77, 1000-peer scale receipt | [iBGP route reflector at scale](cookbook/route-reflector.md) |
| M74, M75, M77, VPN scale receipt | [L3VPN route reflector](cookbook/l3vpn-route-reflector.md) |
| M24, M81 | [Controller / monitoring feed](cookbook/monitoring-feed.md) |
| M29, M30, M31, M32, M33, M82 | [EVPN fabric route reflector](cookbook/evpn-fabric-rr.md) |
| M34, M80 | [Policy quickstart (`.rpol`)](cookbook/policy-quickstart.md) |

## Interop labs — PR-gated (`interop.yml`)

These run on every pull request via
[`.github/workflows/interop.yml`](../.github/workflows/interop.yml); the job
id matches the milestone. Full procedures: [`INTEROP.md`](INTEROP.md).

| Receipt | Proves | Peer stack |
|---------|--------|------------|
| M1 | Basic session + UPDATE receive into the RIB | FRR 10.3.1 |
| M10 | IPv6 dual-stack MP-BGP (MP_REACH_NLRI) | FRR 10.3.1 |
| M13 | Policy engine: import chains, export deny/MED/prepend (3-node) | FRR 10.3.1 |
| M14 | Route reflector (RFC 4456): ORIGINATOR_ID, CLUSTER_LIST, reflection | FRR 10.3.1 |
| M15 | Route Refresh (RFC 2918) via gRPC SoftResetIn | FRR 10.3.1 |
| M17 | Add-Path (RFC 7911) multi-path send with distinct path ids | FRR 10.3.1 |
| M22 | FlowSpec inject + distribute + withdraw | FRR 10.3.1 |
| M24 | BMP Initiation, PeerUp, RouteMonitoring ordering | FRR + BMP receiver |
| M25 | TCP MD5 authentication + GTSM/TTL security | FRR 10.3.1 ×2 |
| M29 | EVPN RR capability sanity (RFC 7432) + `ListEvpnRoutes` | FRR 10.3.1 |
| M30 | EVPN Type 2 MAC reflection end-to-end with kernel VXLAN VTEPs | FRR 10.3.1 ×2 |
| M34 | SIGHUP policy soft-reset auto-fire | FRR 10.3.1 |
| M35 / M35b / M35c | RFC 8326 Graceful Shutdown: receiver + initiator legs across unicast, FlowSpec, and EVPN | FRR 10.3.1 |
| M41 | RFC 7999 BLACKHOLE receiver scoping + opt-in kernel FIB discard | FRR 10.3.1 |
| M44 | ADR-0064 gRPC tier authorization over native mTLS | grpcurl |
| M45 | EVPN Type 5 control-plane injection via gRPC (RFC 9136) | FRR 10.3.1 |
| M54 | ADR-0070 gNMI / OpenConfig telemetry + Set over mTLS | gnmic 0.46.0 |
| M55 | BGP Roles + Only-to-Customer leak prevention (RFC 9234) | FRR 10.3.1 ×5 |
| M56 | gNMI `Subscribe ON_CHANGE` session-state stream | gnmic + FRR |
| M57 | Receive-side Address-Prefix ORF (RFC 5291/5292) | FRR 10.3.1 |
| M63 | ADR-0078 inbound backpressure: hold-timer survival under a stalled RIB | FRR 10.3.1 |
| M64 | IPv6-only peering (`disable_ipv4_unicast`) | FRR 10.3.1 |
| M73 | BGP-LS route reflection: source → RR → sink, attributes verbatim | GoBGP 4.6.0 ×2 |
| M74 | VPNv4 (SAFI 128) reflection: RD/label/RT/next-hop preserved verbatim | GoBGP 3.37.0 ×2 |
| M75 | RT-Constrain (RFC 4684) VPNv4 reflection filtering, widen/narrow without reset | GoBGP 3.37.0 ×3 |
| M76 | RFC 9107 Optimal Route Reflection: divergent per-vantage best paths, topology-driven flip | GoBGP 4.6.0 ×5 |
| M77 | GR/LLGR stale preservation for the RR families (RFC 4724 + RFC 9494) | GoBGP 4.6.0 ×3 |
| M78 | Multi-cluster ORR + inter-RR Add-Path | GoBGP 4.6.0 ×5 + rustbgpd ×2 |
| M79 | RFC 8277 labeled-unicast (SAFI 4) reflection + GR | GoBGP 4.6.0 ×2 |
| M80 | ADR-0096 `.rpol` policy parity vs FRR route-maps (dual-family, asn-set origin-AS + `route.family` predicates), hot-apply under traffic | FRR 10.3.1 ×3 |
| M81 | BMP trio (rib-in, rib-out, loc-rib) + BMPv4 against three independent decoders | GoBGP ×2 + pmacct + gobmp + tshark |
| M82 | ADR-0092 EVPN VLAN-Aware Bundle (non-zero Ethernet Tag) reflection: tag as route identity, same MAC under two tags uncollapsed, tag-verbatim NLRIs, tag-scoped withdraw — synthetic leg in CI plus the **first vendor-NOS receipt** (local lab) | GoBGP 3.37.0 ×2 (CI) + Nokia SR Linux 25.10.1 (local) |
| M83 | RFC 7947 route-server profile, multi-stack: byte-level transparency, OTC, per-member views, ROV explain, and the §2.3 path-hiding contrast (single-best / per-client-best / Add-Path, ADR-0101) | BIRD 2.0.12 + GoBGP 3.37.0 + FRR 10.3.1 + StayRTR |

## Interop labs — kernel dataplane, PR + nightly (`kernel-dataplane.yml`)

Privileged containerlab/netns receipts on hosted runners via
[`.github/workflows/kernel-dataplane.yml`](../.github/workflows/kernel-dataplane.yml)
(PRs, pushes to `main`, nightly 07:00 UTC, manual dispatch). Kernel claims are
proved with kernel evidence (routes, FDB rows, nexthop groups, netdev state).

| Receipt | Proves | Peer stack |
|---------|--------|------------|
| M36 | EVPN VTEP receive-side Linux FDB programming | FRR 10.3.1 |
| M37 / M37+IP | EVPN local MAC (+MAC/IP) Type 2/Type 3 origination from kernel observation | FRR 10.3.1 |
| M38 | EVPN multi-homing DF election + Type 1/4 origination | rustbgpd ×2 |
| M39 | EVPN symmetric Interface-less IRB (Type 5 / L3VNI) bidirectional | FRR 10.3.1 |
| M39b | Auto-derived Route Targets cross-vendor (RFC 8365 `AS:VNI`) | FRR 10.3.1 |
| M40 | ADR-0059 EVPN aliasing dataplane ECMP via FDB nexthop groups | FRR EVPN-MH |
| M42 | ADR-0061 opt-in general unicast Linux FIB runtime | FRR 10.3.1 |
| M43 | TCP-AO dynamic `/24` queued-child receipt plus live SIGHUP successor/no-flap proof (probed; skips only if the runner kernel lacks TCP-AO) | BIRD 3.3.1 |
| M46 | RFC 8584 Highest Random Weight DF election | rustbgpd ×2 |
| M47 / M48 | ADR-0063 runtime EVPN tenant teardown (control plane / kernel L3 datapath) | FRR 10.3.1 |
| M49 / M69 | RFC 9785 Highest-Preference DF election (rustbgpd↔rustbgpd and cross-vendor) | rustbgpd ×2 / FRR |
| M50 / M52 | ADR-0066 unicast multipath ECMP FIB install + multipath-relax | FRR 10.3.1 ×2 |
| M51 | ADR-0067 single-hop BFD + RFC 5882 BGP coupling | FRR 10.3.1 |
| M53 | ADR-0069 BGP unnumbered / IPv6 link-local peering + scoped FIB | FRR 10.3.1 ×2 |
| M58 | ADR-0061 runtime `[[fib_tables]]` CRUD over gRPC/CLI | FRR 10.3.1 |
| M60 / M61 / M62 | ADR-0079 adoption sweeps: kill-and-restart reaping/re-adoption for FDB, EVPN L3, and BLACKHOLE state | FRR 10.3.1 |
| M65 | ADR-0083 single-active failover blackout measurement | GoBGP 3.x ×2 |
| M66 / M67 | ADR-0084/0085 Ethernet Segment drain: operator handover and link-driven failover | rustbgpd ×3 |
| M68 | ADR-0087 native GW-IP overlay-index Type 5, FRR consume-side recursion | FRR 10.3.1 |
| M70 | ADR-0089 VLAN-aware bridge FDB attribution | FRR 10.3.1 |
| M71 / M72 | RFC 9136 §4.3 ESI overlay-index Type 5 receive: single-active and all-active recursion | GoBGP 3.x |
| netns selectors | Docker-harness privileged selectors (`fdb_nhg`, `fib_runtime`, `bfd_runtime`, `svd_fdb_vni`, managed-netdev lifecycle, L3 multipath/writer, …) | Linux kernel |

## Interop labs — manual / local gates

Documented drivers that stay off PR CI (long wall clock, extra fixtures, or
covered by later CI receipts). Procedures and results:
[`INTEROP.md`](INTEROP.md).

| Receipt | Proves | Peer stack |
|---------|--------|------------|
| M0 | Session establishment, restart/reset recovery, 30-min soak | FRR 10.3.1 and BIRD 2.0.12 |
| M2 | Best-path selection + `ListBestRoutes` pagination | FRR 10.3.1 |
| M3 | Redistribution, split horizon, injection, withdrawal propagation | FRR 10.3.1 ×2 |
| M4 | Route-server mode: 10-peer static + dynamic neighbor management | FRR 10.3.1 |
| M11 | Graceful Restart (RFC 4724): stale marking, EoR, timer sweep | FRR 10.3.1 |
| M12 | Extended Communities (RFC 4360) receive + inject | FRR 10.3.1 |
| M16 | LLGR (RFC 9494): GR→LLGR transition, stale clearing | FRR 10.3.1 |
| M18 | Extended Next-Hop (RFC 8950): IPv6 next hop for IPv4 NLRI | FRR 10.3.1 |
| M19 | Transparent route server: no ASN prepend, NH preservation | FRR 10.3.1 |
| M20 | Private AS removal (remove/all/replace) | FRR 10.3.1 |
| M21 | RPKI origin validation via RTR | FRR + StayRTR |
| M23 | Bidirectional route exchange with GoBGP | GoBGP 4.3.0 |
| M26 | Max-prefix teardown latch + explicit recovery (Cease/1 without Notification GR) | FRR 10.3.1 |
| M27 / M59 | ASPA via RTR v2: validation states, best-path preference, role-aware downstream verification | FRR + RTR v2 mock |
| M28 | Dynamic prefix-based neighbors: auto-accept, auto-remove | FRR 10.3.1 |
| M30b | EVPN Type 5 IP-prefix origination (RFC 9136) with kernel VRF/L3VNI | FRR 10.3.1 |
| M31 | EVPN MAC mobility + sticky preservation (RFC 7432 §15.1/§7.7) | FRR 10.3.1 ×3 |
| M32 / M32b | EVPN multi-homing Type 1 EAD + Type 4 ES reflection (kernel bond / synthetic ESI) | FRR 10.3.1 ×3 |
| M33 | EVPN RR scale: 50k Type 2 routes + 60 s of 1000/s churn | in-tree `bench/evpn-load` |
| M84 | Multi-cache RTR/ASPA epoch conformance (LAN-243): per-cache load at validated EoD, v2→v1 fallback, restart retention + session rotation, ASPA replace / empty-provider withdrawal, serial-regression resync | FRR + Routinator 0.15.2 + StayRTR + RTR v2 mock |
| M90 | ADR-0110 filtering differential: one arouteserver site produces BIRD and rustbgpd policy, with exact verdict/explain parity over 11 announcements and a red-producing policy mutation | BIRD 2.0.12 + GoBGP 3.37.0 ×3 + arouteserver 1.23.2 |

## Performance and scale receipts

| Receipt | What it measures | Source |
|---------|------------------|--------|
| 1000-peer RR scale receipt | Real `RibManager` + 1000 real transport sessions over loopback: 100k-route cold convergence, policy-on, mixed-fleet, and churn, with the profile-to-fix storyline behind the ADR-0098 update-groups arc | [`perf/scale-receipt-2026-07.md`](perf/scale-receipt-2026-07.md) |
| 1000-peer VPN scale receipt (update-groups v2) | 100k VPNv4 to 1000 RR clients, uniform and heterogeneous ~10% RT-membership shapes, plus the one-RT membership-flip wire latency (~15 ms at 100k staged, zero policy evals) — the ADR-0099 receipt | [`perf/scale-receipt-2026-07.md`](perf/scale-receipt-2026-07.md) (Scenario E) |
| Reload UPDATE-stall receipt (LAN-333) | Accepted 700-client × 400,400-route run: the corrected gate verifies every expected unique prefix at the requested policy generation for all 700 clients; median stall p50 is 0.76 s and the worst observer is 0.82 s | [`perf/reload-stall-2026-07.md`](perf/reload-stall-2026-07.md) |
| IXP route-server receipt matrix | rustbgpd vs BIRD 3.3.1 vs OpenBGPD 9.1 at 700 clients × 400,400 routes through the same harness on the same host: reload stall + completion (two independent runs), flapstorm withdraw/re-announce (rustbgpd fastest on both: re-announce p50 0.46–0.49 s vs BIRD's 2.8–4.2 s and OpenBGPD's 21–22 s), convergence, and process-tree RSS, each incumbent at its documented strongest configuration, losses published alongside wins (OpenBGPD's smaller stall, BIRD's lower RSS) — including a post-publication note where the receipt's own S3 tables exposed a re-announce plateau that was root-caused, fixed, and rerun (9.5–9.8 s → 0.46–0.49 s) | [`perf/ixp-matrix-2026-07.md`](perf/ixp-matrix-2026-07.md) |
| Mixed policy-reload cohort campaign | 700 sessions and 400,400 routes with 600 changed / 100 stable peers: completion p50 / maximum improve 116.185x / 149.261x, while full-fleet delivery-gap p50 / maximum regress 2.070x / 2.899x; every row retains 700/700 sessions, 100/100 fresh stable markers, and zero parse errors | [`perf/artifacts/policy-reload-cohort-partition-2026-07/README.md`](perf/artifacts/policy-reload-cohort-partition-2026-07/README.md), [`REPRODUCE.md`](perf/artifacts/policy-reload-cohort-partition-2026-07/REPRODUCE.md) |
| RIB operations (Criterion) | Ingest, best-path, distribution microbenchmarks with pinned A/B compare methodology | [`BENCHMARKS.md`](BENCHMARKS.md#rib-operations) |
| Exact-export fanout optimization (Criterion + rrharness) | Three pinned campaigns: ordered prepared-attribute memo (18%..32% faster), bounded wire-equivalent update-group probe reuse (58%..64% faster at 256 peers vs pre-cache), then lazy grouped exact-precommit bookkeeping (32%..36% faster at 64/256 peers and +197%..+649% across the manager flood/churn matrix), with fail-closed sealed artifacts, confidence gates, and correctness fences | [`perf/exact-export-fanout-2026-07.md`](perf/exact-export-fanout-2026-07.md) |
| Per-peer policy-fallback handoff | 65,536-route fallback decision plus one authoritative apply: 104.25 ms mean and 110.011 ms largest retained per-iteration sample; a structural 64-peer RIB-loop reference demonstrates why returning to the actor loop between applies protects availability. No total-work gain is claimed | [`perf/policy-fallback-per-peer-handoff-2026-07.md`](perf/policy-fallback-per-peer-handoff-2026-07.md) |
| Grouped RIB route paging | Pinned four-repetition traversal matrix: 400k grouped listings improve 9.342x at page 100 and 8.086x at page 1,000 after removing per-page full-view clones; exact raw rows, preflights, sources, and checksums are retained | [`perf/rib-route-paging-2026-07.md`](perf/rib-route-paging-2026-07.md) |
| End-to-end bgperf2 | Same-host convergence/CPU/RSS comparison vs BIRD and GoBGP | [`BENCHMARKS.md`](BENCHMARKS.md#end-to-end-system-benchmarks) |
| High-N RIB memory | Structural memory at 100k/500k/900k prefixes; A/B via `bench/compare-rib-memory.sh` under the shared host lock | [`BENCHMARKS.md`](BENCHMARKS.md#memory-footprint), [`../bench/README.md`](../bench/README.md) |
| EVPN M33 load gate | 50k reflected Type 2 routes + 60 s of 1k-rps churn | [`BENCHMARKS.md`](BENCHMARKS.md#evpn-rr-scale-m33) |

## Soak receipts

Archived long-running runs with pass/fail gates, RSS slopes, and git-tracked
artifacts under [`artifacts/soak/`](artifacts/soak/). Harnesses live in
[`../tests/soak/`](../tests/soak/README.md).

| Receipt | Duration | What it proves |
|---------|----------|----------------|
| [Gate 8b BUM-state](soaks/soak-gate8b-24h-bum-state.md) | 24 h | BUM-port flag triplet survives 71 DF-flip cycles; flat RSS |
| [Gate 8b MAC-churn dry run](soaks/soak-gate8b-mac-churn-1h.md) | 1 h | Dry run gating the 24 h MAC-churn soak |
| [Gate 8b MAC-churn](soaks/soak-gate8b-mac-churn-24h.md) | 24 h | 69 post-flip reconverges under MAC churn; zero WARN/FATAL; ~0.08 MB/h envelope |
| [Gate 8b MAC-churn leak A/B](soaks/soak-gate8b-mac-churn-10h-leak.md) | ~10 h | EVPN attribute-intern table bounded under churn across DF flips (MAC-mobility leak fix, churn axis) |
| [Gate 9 symmetric IRB](soaks/soak-gate9-slice6-24h-symmetric-irb.md) | 24 h | 703 Type 5 churn cycles; zero session or installed-route violations |
| [M33 EVPN scale leak A/B](soaks/soak-m33-evpn-scale-10h-leak.md) | ~10 h | Attribute-intern table bounded at 50k Type 2 routes + churn (leak fix, scale axis) |
| [M37 local-origination churn](soaks/soak-m37-local-origination-churn-24h.md) | 24 h | 430,400 injects balanced by 430,400 withdraws; zero flaps |
| [M67 link-drain MAC-mobility](soaks/soak-m67-link-drain-24h-evpn-leak.md) | 24 h | 960 link-drain failover cycles with live MAC-mobility churn; all six RSS gates flat; blackout ≤ 300 ms |

## Continuous verification — CI schedules

| Workflow | Trigger | What it re-proves |
|----------|---------|-------------------|
| [`ci.yml`](../.github/workflows/ci.yml) | every PR / push | fmt, clippy (warnings denied), workspace tests, rustdoc, kernel-primitive gate |
| [`interop.yml`](../.github/workflows/interop.yml) | every PR / push | The PR-gated M-series table above, one containerlab job per milestone |
| [`kernel-dataplane.yml`](../.github/workflows/kernel-dataplane.yml) | PR, push, nightly 07:00 UTC | Privileged EVPN/FIB/BFD/TCP-AO dataplane receipts + netns selectors |
| [`fuzz.yml`](../.github/workflows/fuzz.yml) | nightly 04:00 UTC + manual dispatch | libFuzzer wire, policy, EVPN route-target, MRT snapshot, and warm-bundle manifest harnesses |
| [`bench-nightly.yml`](../.github/workflows/bench-nightly.yml) | nightly 05:00 UTC | Benchmark tracking on the bench runner |
| [`audit.yml`](../.github/workflows/audit.yml) | daily 06:00 UTC | `cargo audit` / dependency advisories |
| [`privileged-interop.yml`](../.github/workflows/privileged-interop.yml) | manual dispatch | Direct-`cargo` privileged netns suites |

## Adding a receipt

Write the detailed source document first (interop procedure in
[`INTEROP.md`](INTEROP.md), soak postmortem as `docs/soaks/soak-*.md` with artifacts
under `docs/artifacts/soak/<run-id>/`, perf receipt under `docs/perf/`), then
add the row here and in [`OPERATIONAL_PROOF.md`](OPERATIONAL_PROOF.md).
