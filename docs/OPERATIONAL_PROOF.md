# Operational Proof Receipts

This page is the roll-up view of rustbgpd's operational evidence. It links to
the primary receipts for interop, dataplane, scale, benchmark, memory, and soak
coverage. Detailed procedures stay in the source documents; this page is the
operator-facing index that answers "what has actually been proved?"

## Current proof posture

| Surface | Current receipt | Primary source |
|---------|-----------------|----------------|
| Workspace correctness | Unit, integration, async, and policy tests run through `cargo test --workspace`. | `cargo test --workspace`; release notes in [`../CHANGELOG.md`](../CHANGELOG.md) |
| Update-group fault differential | A fixed PR corpus compares grouped and forced-per-peer output under saturation/retry, dirty regroup, session replacement, stale generations, Add-Path cap changes, and RTC/ORF membership churn. A combined schedule also interleaves saturation, a dirty policy regroup, and current/superseded session traffic. A current-session terminal sentinel rejects equal-but-incomplete streams; a hard-capped 24-seed extension runs weekly and on manual dispatch on GitHub-hosted runners. On failure, the workflow preserves the original nonzero result while a bounded, process-isolated reducer appends an exact seed/scenario/original-operation replay and its complete-single-deletion-pass status to the failure-only log artifact. | `cargo test -p rustbgpd-rib deterministic_fault_corpus`; [replay and minimization instructions](../CONTRIBUTING.md#replaying-update-group-faults); [workflow](../.github/workflows/update-group-fault.yml) |
| Wire robustness | libFuzzer harnesses cover message and attribute decoding, with CI smoke and nightly extended jobs. | [`../README.md`](../README.md#testing-and-correctness) |
| Foundation interop | PR-gated containerlab coverage for core RIB, refresh, policy, MP-BGP, RR, multipath, BMP, security, FlowSpec, EVPN sanity, graceful shutdown, BLACKHOLE FIB discard, gRPC/gNMI, and ORF/gNMI Set smokes. | [`INTEROP.md`](INTEROP.md#ci-coverage) |
| Privileged dataplane interop | Hosted GitHub `kernel-dataplane` workflow covers EVPN VTEP/IRB, FIB, BFD, TCP-AO where supported, and Linux netns dataplane selectors. | [`kernel-dataplane-runner.md`](kernel-dataplane-runner.md), [`INTEROP.md`](INTEROP.md#ci-coverage) |
| Performance and scale | Criterion, bgperf2, distribution fanout, EVPN load, and RIB memory measurements are documented with hardware, noise floor, and measurement state. | [`BENCHMARKS.md`](BENCHMARKS.md) |
| High-N memory regression tracking | Ignored RIB memory profile covers Adj-RIB-In, Full-RIB, and RR/route-server fanout at 100k/500k/900k prefixes; A/B summaries come from `bench/compare-rib-memory.sh`. | [`BENCHMARKS.md`](BENCHMARKS.md#memory-footprint), [`../bench/README.md`](../bench/README.md#rib-memory-compare) |
| Long-running soak evidence | Archived 24-hour EVPN and local-origination soaks include run metadata, pass/fail gates, RSS slopes, and git-tracked artifacts. | [Soak receipts](#soak-receipts) |
| EVPN link-drain churn soak | Archived M67 24-hour run covers the single-active ES link-drain surface with route/session/gauge/timing/RSS gates under live MAC-mobility churn. | [`soak-m67-link-drain-24h-evpn-leak.md`](soaks/soak-m67-link-drain-24h-evpn-leak.md), [`../tests/soak/README.md`](../tests/soak/README.md#m67-link-drain-churn-soak) |

## Interop and dataplane receipts

| Receipt | Status | Notes |
|---------|--------|-------|
| Foundation M-series interop | CI-gated on every PR | `interop.yml` covers the core protocol and management surfaces listed in [`INTEROP.md`](INTEROP.md#ci-coverage), including M73's GoBGP 4.6.0 BGP-LS source -> rustbgpd RR -> GoBGP sink reflection / withdrawal receipt, M74's GoBGP 3.37.0 VPNv4 (SAFI 128) reflection receipt (RD / MPLS label / RT / next-hop preserved verbatim, RD-scoped identity, withdrawal propagation, no dataplane install), M75's GoBGP 3.37.0 RT-Constrain (RFC 4684, SAFI 132) VPNv4 reflection-filtering receipt (default-RTC NLRI accepted into GoBGP adj-in, strict per-peer filtering, widen/narrow membership without session reset, unfiltered delivery to a non-RTC peer, no dataplane install, no reflection storm), and M76's GoBGP 4.6.0 RFC 9107 Optimal Route Reflection receipt (injected BGP-LS square, divergent per-vantage best paths to two RR clients for one prefix, topology-driven flip moving only the bound client with zero churn to the other, fallback to one identical standard best on LSDB withdrawal, re-inject recovery, no dataplane install, plus the no-flap pin on the linkstate-only source session — the wire regression pin for the #632 implicit-IPv4 negotiation fix), and M80's ADR-0096 `.rpol` policy-parity receipt against FRR 10.3.1 (route-for-route import/export outcome equality vs route-maps expressing the same intent across IPv4 and IPv6 unicast on the same MP-BGP sessions — including asn-set origin-AS probes and family-branched terms whose same-origin v4/v6 twins diverge purely by `route.family` — `rbgp policy check`/`test`/`stats` in both directions, explain traces naming the deciding source term, and an `.rpol` edit under traffic hot-applying with zero flap and Route Refresh scoped to exactly the peer whose resolved chain changed). |
| Hosted kernel dataplane | CI-gated on PRs, pushes to `main`, nightly, and manual dispatch | Uses GitHub-hosted `ubuntu-latest` runners with privileged containerlab/netns setup. EVPN receipts include M68 for FRR consumption of rustbgpd's native GW-IP overlay-index Type 5, M71 for rustbgpd's receive-side RFC 9136 §4.3 ESI overlay-index Type 5 single-active recursion against a GoBGP route source, M72 for the all-active ESI overlay-index Type 5 receive path against two GoBGP route sources, M70 for ADR-0089 VLAN-aware bridge FDB attribution, the `svd_fdb_vni` netns selector for LAN-64 SVD Ready/programming, `managed_bridge` / `managed_vxlan` / `managed_vlan_upper` / `managed_ready` / `managed_ip_vrf_ready` for ADR-0091 managed netdev lifecycle and readiness, `l3_multipath` for LAN-70's all-active Type 5 kernel-mechanism proof, and `l3_all_active_writer` for LAN-76/LAN-77's production all-active Type 5 L3 writer plus restart-adoption proof. The SVD selector proves collect-metadata / `vnifilter` detection, Ready status, `NDA_SRC_VNI` FDB programming, same-MAC two-VNI isolation, and scoped delete on a real kernel. The managed-netdev selectors prove bridge, fixed-VNI VXLAN, VLAN upper, VRF, and L3VXLAN create/adopt/reap behavior; `managed_ready` drives the real EVPN L2 probe from NotReady to Ready, and `managed_ip_vrf_ready` drives the real IP-VRF probe from NotReady to Ready on a real kernel. The L3 multipath selector proves route-level multipath over one L3VXLAN, same-Router-MAC single-dst FDB collapse, and FDB-NHG viability on the L3VXLAN device; the L3 writer selector drives a real `ReconcileActor<LinuxDataplane>` to install and withdraw the ECMP route, per-VTEP L3 neighbors, L3-tagged FDB-NHG members, Router-MAC `nhid` FDB row, cleanup path, and abort/restart adoption of the same kernel state. M72 proves the same all-active receive path from real GoBGP EVPN routes: unresolved hold, two-way VRF ECMP import, Router-MAC FDB-NHG state, target-set collapse/re-expand, and withdraw cleanup. TCP-AO topologies are probed and skipped only if the runner kernel lacks support. The vrf-dependent EVPN L3 receipts (M39 / M39b / M48 / M61 / M68 / M71 / M72 and the `managed_ip_vrf_ready` / `l3_multipath` / `l3_all_active_writer` netns selectors) are gated on `vrf` availability: when the hosted runner kernel rolls ahead of the matching `linux-modules-extra` package in the apt mirror the module cannot load, so those receipts skip with a notice rather than fail — a transient runner-image condition, not a rustbgpd regression, and they resume automatically once the mirror catches up. |
| BIRD / GoBGP / StayRTR diversity | Mixed CI/manual | BIRD TCP-AO and GoBGP coverage are documented; RTR-dependent RPKI/ASPA cases and broader platform-diversity runs remain local/manual where extra fixtures are required. |
| Long-wall-clock gates | Manual/local | GR/LLGR soak-style gates and M33 scale churn are intentionally not PR-CI jobs because they consume substantial wall-clock. |

Compact M36-M90 index (details and assertions stay in
[`INTEROP.md`](INTEROP.md#ci-coverage)):

| Receipts | Coverage |
|----------|----------|
| M36, M37, M37+IP | EVPN L2 VTEP FDB programming plus local Type 2 / Type 3 / MAC+IP origination. |
| M38, M40, M46, M49, M65, M66, M67, M69 | EVPN multi-homing: DF election, aliasing/FDB-NHG, single-active backup swap, runtime drain, link drain, and FRR preference-DF interop. |
| M39, M39b, M47, M48, M60, M61, M68, M70, M71, M72 | EVPN L3VNI / Type 5 / runtime convergence / adoption / VLAN-aware / overlay-index dataplane receipts. |
| M42, M50, M51, M52, M53, M58, M62 | Non-EVPN kernel dataplane receipts in the same hosted span: FIB runtime/CRUD, BFD, BGP unnumbered, and BLACKHOLE adoption. |
| M43 | Conditional TCP-AO queued-child receipt, uninterrupted no-flap add/select/deprecate/delete against BIRD with a 100 ms route-continuity oracle, and a separate three-phase SIGKILL/restart recovery gate requiring exact fresh-start inventory/auth/session state; probed and skipped only when the selected runner kernel lacks support. |
| Other M41-M90 rows in this span | Foundation interop receipts such as BLACKHOLE FIB discard, gRPC/gNMI, EVPN Type 5 injection, BGP Roles/ORF/ASPA, inbound backpressure, IPv6-only peering, BGP-LS reflection, VPNv4 route-reflection, RT-Constrain VPNv4 filtering, RFC 9107 ORR divergent-best, RR-family GR/LLGR stale preservation, multi-cluster ORR with inter-RR Add-Path, RFC 8277 labeled-unicast reflection + GR, ADR-0096 `.rpol` policy parity vs FRR route-maps (M80), BMP trio + BMPv4/path-marking against pmacct/gobmp/tshark (M81), EVPN VLAN-aware-bundle non-zero Ethernet Tag reflection (M82), RFC 7947 route-server profile transparency/path-hiding/ROV proof (M83), and the arouteserver/BIRD/rustbgpd filtering differential (M90) remain catalogued in `INTEROP.md`. |

## Scale and benchmark receipts

| Receipt | Status | Notes |
|---------|--------|-------|
| 1000-peer RR scale receipt | Documented same-host measurement | Real `RibManager` + 1000 real transport sessions over loopback: 100k-route cold convergence, policy-on, mixed-fleet, and churn tables with the profile-to-fix storyline are in [`perf/scale-receipt-2026-07.md`](perf/scale-receipt-2026-07.md). |
| RIB operations Criterion suite | Documented A/B methodology | Current `main` medians and cumulative deltas are in [`BENCHMARKS.md`](BENCHMARKS.md#rib-operations). |
| MRT snapshot allocation control (LAN-572) | Pinned quiet-host production-encoder control | The IXP-many-source and dual-full-feed controls retain 0.359%/0.367% population timing CV, 6.81M/10.41M output-growth misses, exact allocator equations, semantic reader oracles, checksummed preflight/mutation receipts, and the predeclared immediate-parent ABBA rules required before any candidate claim in [`perf/mrt-snapshot-allocation-2026-07.md`](perf/mrt-snapshot-allocation-2026-07.md). |
| End-to-end bgperf2 | Documented cross-stack comparison | Same-host rustbgpd/BIRD/GoBGP convergence, CPU, and RSS results are in [`BENCHMARKS.md`](BENCHMARKS.md#end-to-end-system-benchmarks). |
| Distribution fanout | Pinned multi-campaign receipt | Real per-session exact-probe baseline vs prepared-attribute memo (18%..32% gains), bounded wire-equivalent update-group probe reuse (58%..64% faster at 256 peers vs pre-cache), then lazy clean-group exact-precommit bookkeeping (32%..36% faster at 64/256 peers; +197%..+649% in the 16-cell manager flood/churn matrix). Exact refs, counterbalanced orders, confidence gates, host preflights, correctness fences, and checksummed sealed artifacts are in [`perf/exact-export-fanout-2026-07.md`](perf/exact-export-fanout-2026-07.md). |
| Adj-RIB-Out family-gauge fanout | Pinned real-encoder A/B receipt | For one homogeneous route-server update group with 64 changed routes, touched-family metric refresh improves the measured actor/probe/commit/enqueue interval by 11.69% at 256 peers and 14.98% at 1,000 peers. The receipt includes path assertions, load-bearing regressions, counterbalanced pairs, regression controls, checksummed artifacts, and explicit worst-case/cardinality costs in [`perf/adj-rib-out-family-gauge-2026-07.md`](perf/adj-rib-out-family-gauge-2026-07.md). |
| Per-peer policy-fallback handoff | Documented availability bound | At 65,536 routes, the fallback decision plus one authoritative RIB apply measured 104.25 ms mean with a 110.011 ms largest retained iteration. A structural 64-peer reference demonstrates the multi-peer actor-stall shape; no total-work improvement is claimed. Exact sources, claim boundaries, raw samples, and checksums are in [`perf/policy-fallback-per-peer-handoff-2026-07.md`](perf/policy-fallback-per-peer-handoff-2026-07.md). |
| High-N RIB structural memory | Repeatable harness | `bench/compare-rib-memory.sh` emits CSV plus Markdown receipts for 100k/500k/900k shapes under the shared bench/soak host mutex. |
| EVPN M33 load | In-tree scale gate | `bench/evpn-load` covers 50k reflected Type 2 routes with 60 seconds of 1k-rps churn. |

## Soak receipts

| Receipt | Verdict | Key signals | Artifacts |
|---------|---------|-------------|-----------|
| [Gate 8b BUM-state 24h](soaks/soak-gate8b-24h-bum-state.md) | PASS | 24h 00m 32s; 71 complete DF-flip cycles; PE1 RSS steady-state slope 0.000 MB/h after settle; BUM-port flag triplet survived every sampled flip. | [`artifacts/soak/gate8b-20260510T152451Z/`](artifacts/soak/gate8b-20260510T152451Z/) |
| [Gate 8b MAC-churn 24h](soaks/soak-gate8b-mac-churn-24h.md) | PASS | 24h 0m 14s; 69 post-flip reconverges; zero WARN/FATAL/topology-link-loss events; PE1 peak RSS 18.93 MB and post-settle envelope about 0.08 MB/h. | [`artifacts/soak/gate8b-mac-churn-24h-20260515T214043Z/`](artifacts/soak/gate8b-mac-churn-24h-20260515T214043Z/) |
| [Gate 9 symmetric IRB 24h](soaks/soak-gate9-slice6-24h-symmetric-irb.md) | PASS | 24h 00m 44s; 703 churn cycles; zero BGP established violations; zero installed-route violations; PE1 peak RSS 14.3438 MB and steady-state slope 0.025 MB/h. | [`artifacts/soak/gate9-slice6-20260511T214936Z/`](artifacts/soak/gate9-slice6-20260511T214936Z/) |
| [M37 local-origination MAC-churn 24h](soaks/soak-m37-local-origination-churn-24h.md) | PASS | 24h 1m 53s; 17,174 churn cycles; 430,400 injects balanced by 430,400 withdraws; zero session flaps; PE peak RSS 23.531 MB and after-warmup slope 0.184 MB/h. | [`artifacts/soak/m37-local-origination-20260518T015056Z/`](artifacts/soak/m37-local-origination-20260518T015056Z/) |
| [M67 link-drain MAC-mobility 24h](soaks/soak-m67-link-drain-24h-evpn-leak.md) | PASS | 24h; 960 link-drain failover cycles with live MAC-mobility churn; all six RSS gates flat at 0.006-0.016 MB/h; blackout max 300 ms; corrected sampler gate shows no sustained session-loss window. | [`artifacts/soak/m67-link-drain-20260628T141945Z/`](artifacts/soak/m67-link-drain-20260628T141945Z/) |

## Known proof gaps

- Continuous or multi-day soak automation beyond the archived 24-hour receipts
  remains future work. The harnesses exist, but a standing soak runner is not
  currently part of normal CI.
- bgperf2 end-to-end comparison is a documented same-host receipt, not a PR-CI
  gate. Criterion comparison is easy to dispatch on the bench runner, but its
  output is reviewer input until a lower-noise host is available.
- Some interop rows require local fixtures or longer runtime and remain manual:
  RTR-cache-driven RPKI/ASPA tests, selected BIRD/GoBGP/platform-diversity
  checks, and GR/LLGR long-wall-clock gates.
- EVPN is still alpha. The archived soaks prove specific gates and defaults;
  they do not claim full EVPN/MPLS/PBB/MVPN parity.

## Refreshing the receipts

When adding a new proof point, update the detailed source document first and
this roll-up second. Keep this page short enough that operators can scan it.
New M-series receipts should also satisfy the proof-quality contract in
[`INTEROP.md`](INTEROP.md#m-series-proof-quality-contract).

Useful commands and entry points:

```bash
cargo test --workspace --no-fail-fast
cargo clippy --workspace --all-targets -- -D warnings
cargo doc --workspace --no-deps  # -D warnings pinned in .cargo/config.toml
cargo test -p rustbgpd-rib deterministic_fault_corpus

bench/compare-criterion.sh --package rustbgpd-rib --bench rib_ops
bench/compare-rib-memory.sh --base origin/main --head HEAD --profile quick
```

For interop, start from [`INTEROP.md`](INTEROP.md). For soak runs, archive the
small load-bearing files under `docs/artifacts/soak/<run-id>/` and write or
refresh the matching `docs/soaks/soak-*.md` postmortem. Redact absolute local
checkout paths (replace the `.../rustbgpd` prefix with `<repo>`) in archived
`run.json` / `soak.log` files before committing.
