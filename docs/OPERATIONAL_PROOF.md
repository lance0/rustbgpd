# Operational Proof Receipts

This page is the roll-up view of rustbgpd's operational evidence. It links to
the primary receipts for interop, dataplane, scale, benchmark, memory, and soak
coverage. Detailed procedures stay in the source documents; this page is the
operator-facing index that answers "what has actually been proved?"

## Current proof posture

| Surface | Current receipt | Primary source |
|---------|-----------------|----------------|
| Workspace correctness | Unit, integration, async, and policy tests run through `cargo test --workspace`. | `cargo test --workspace`; release notes in [`../CHANGELOG.md`](../CHANGELOG.md) |
| Wire robustness | libFuzzer harnesses cover message and attribute decoding, with CI smoke and nightly extended jobs. | [`../README.md`](../README.md#testing-and-correctness) |
| Foundation interop | PR-gated containerlab coverage for core RIB, refresh, policy, MP-BGP, RR, multipath, BMP, security, FlowSpec, EVPN sanity, graceful shutdown, BLACKHOLE FIB discard, gRPC/gNMI, and ORF/gNMI Set smokes. | [`INTEROP.md`](INTEROP.md#ci-coverage) |
| Privileged dataplane interop | Hosted GitHub `kernel-dataplane` workflow covers EVPN VTEP/IRB, FIB, BFD, TCP-AO where supported, and Linux netns dataplane selectors. | [`kernel-dataplane-runner.md`](kernel-dataplane-runner.md), [`INTEROP.md`](INTEROP.md#ci-coverage) |
| Performance and scale | Criterion, bgperf2, distribution fanout, EVPN load, and RIB memory measurements are documented with hardware, noise floor, and measurement state. | [`BENCHMARKS.md`](BENCHMARKS.md) |
| High-N memory regression tracking | Ignored RIB memory profile covers Adj-RIB-In, Full-RIB, and RR/route-server fanout at 100k/500k/900k prefixes; A/B summaries come from `bench/compare-rib-memory.sh`. | [`BENCHMARKS.md`](BENCHMARKS.md#memory-footprint), [`../bench/README.md`](../bench/README.md#rib-memory-compare) |
| Long-running soak evidence | Archived 24-hour EVPN and local-origination soaks include run metadata, pass/fail gates, RSS slopes, and git-tracked artifacts. | [Soak receipts](#soak-receipts) |

## Interop and dataplane receipts

| Receipt | Status | Notes |
|---------|--------|-------|
| Foundation M-series interop | CI-gated on every PR | `interop.yml` covers the core protocol and management surfaces listed in [`INTEROP.md`](INTEROP.md#ci-coverage). |
| Hosted kernel dataplane | CI-gated on PRs, pushes to `main`, nightly, and manual dispatch | Uses GitHub-hosted `ubuntu-latest` runners with privileged containerlab/netns setup. TCP-AO topologies are probed and skipped only if the runner kernel lacks support. |
| BIRD / GoBGP / StayRTR diversity | Mixed CI/manual | BIRD TCP-AO and GoBGP coverage are documented; RTR-dependent RPKI/ASPA cases and broader platform-diversity runs remain local/manual where extra fixtures are required. |
| Long-wall-clock gates | Manual/local | GR/LLGR soak-style gates and M33 scale churn are intentionally not PR-CI jobs because they consume substantial wall-clock. |

## Scale and benchmark receipts

| Receipt | Status | Notes |
|---------|--------|-------|
| RIB operations Criterion suite | Documented A/B methodology | Current `main` medians and cumulative deltas are in [`BENCHMARKS.md`](BENCHMARKS.md#rib-operations). |
| End-to-end bgperf2 | Documented cross-stack comparison | Same-host rustbgpd/BIRD/GoBGP convergence, CPU, and RSS results are in [`BENCHMARKS.md`](BENCHMARKS.md#end-to-end-system-benchmarks). |
| Distribution fanout | Documented baseline | Measures the real `RibManager::distribute_changes` fanout path and policy-chain overhead. |
| High-N RIB structural memory | Repeatable harness | `bench/compare-rib-memory.sh` emits CSV plus Markdown receipts for 100k/500k/900k shapes under the shared bench/soak host mutex. |
| EVPN M33 load | In-tree scale gate | `bench/evpn-load` covers 50k reflected Type 2 routes with 60 seconds of 1k-rps churn. |

## Soak receipts

| Receipt | Verdict | Key signals | Artifacts |
|---------|---------|-------------|-----------|
| [Gate 8b BUM-state 24h](soak-gate8b-24h-bum-state.md) | PASS | 24h 00m 32s; 71 complete DF-flip cycles; PE1 RSS steady-state slope 0.000 MB/h after settle; BUM-port flag triplet survived every sampled flip. | [`artifacts/soak/gate8b-20260510T152451Z/`](artifacts/soak/gate8b-20260510T152451Z/) |
| [Gate 8b MAC-churn 24h](soak-gate8b-mac-churn-24h.md) | PASS | 24h 0m 14s; 69 post-flip reconverges; zero WARN/FATAL/topology-link-loss events; PE1 peak RSS 18.93 MB and post-settle envelope about 0.08 MB/h. | [`artifacts/soak/gate8b-mac-churn-24h-20260515T214043Z/`](artifacts/soak/gate8b-mac-churn-24h-20260515T214043Z/) |
| [Gate 9 symmetric IRB 24h](soak-gate9-slice6-24h-symmetric-irb.md) | PASS | 24h 00m 44s; 703 churn cycles; zero BGP established violations; zero installed-route violations; PE1 peak RSS 14.3438 MB and steady-state slope 0.025 MB/h. | [`artifacts/soak/gate9-slice6-20260511T214936Z/`](artifacts/soak/gate9-slice6-20260511T214936Z/) |
| [M37 local-origination MAC-churn 24h](soak-m37-local-origination-churn-24h.md) | PASS | 24h 1m 53s; 17,174 churn cycles; 430,400 injects balanced by 430,400 withdraws; zero session flaps; PE peak RSS 23.531 MB and after-warmup slope 0.184 MB/h. | [`artifacts/soak/m37-local-origination-20260518T015056Z/`](artifacts/soak/m37-local-origination-20260518T015056Z/) |

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

Useful commands and entry points:

```bash
cargo test --workspace --no-fail-fast
cargo clippy --workspace --all-targets -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps

bench/compare-criterion.sh --package rustbgpd-rib --bench rib_ops
bench/compare-rib-memory.sh --base origin/main --head HEAD --profile quick
```

For interop, start from [`INTEROP.md`](INTEROP.md). For soak runs, archive the
small load-bearing files under `docs/artifacts/soak/<run-id>/` and write or
refresh the matching `docs/soak-*.md` postmortem. Redact absolute local
checkout paths (replace the `.../rustbgpd` prefix with `<repo>`) in archived
`run.json` / `soak.log` files before committing.
