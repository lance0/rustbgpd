# rustbgpd documentation

The docs are organized by what you are trying to do
([Diátaxis](https://diataxis.fr/)): **tutorials** to learn, **how-to
guides** to get a task done, **reference** to look something up, and
**explanation** to understand why. Every file in `docs/` is indexed
below under its primary bucket.

<!-- Structure note: these four buckets are the intended top-level
     navigation for the future docs site (PR #704) — keep them in
     sync when adding a page. -->

## Tutorials — learning by doing

Start here if you have never run the daemon.

| Doc | What it teaches |
|-----|-----------------|
| [QUICKSTART.md](QUICKSTART.md) | Single daemon on a host: starter config, gRPC socket, health probes, and the `rbgp` CLI |
| [../examples/docker-compose/](../examples/docker-compose/README.md) | Two-node lab: rustbgpd peered with FRR over Docker Compose, no host setup |
| [../examples/evpn-vtep-leaf/](../examples/evpn-vtep-leaf/README.md) | Leaf-mode EVPN VTEP config walkthrough (iBGP to spine RRs, kernel dataplane) |

## How-to guides — task-oriented recipes and runbooks

| Doc | What it gets done |
|-----|-------------------|
| [cookbook/](cookbook/README.md) | Scenario recipes with receipt-proven configs: RR at scale, L3VPN RR, IXP route server, monitoring feed, EVPN fabric RR, policy quickstart, migration, and the operator runbooks below |
| [cookbook/peer-flap-triage.md](cookbook/peer-flap-triage.md) | Runbook: a peer is flapping — what to look at, in order |
| [cookbook/rr-pair-day2.md](cookbook/rr-pair-day2.md) | Runbook: day-2 operations on a redundant RR pair — GR sanity, adding clients, safe config edits |
| [cookbook/route-server-migration.md](cookbook/route-server-migration.md) | Shadow cutover runbook: map FRR/BIRD/ARouteServer concepts, run the shadow trial, gate cutover on `rbgp diff advertised` |
| [cookbook/ixp-filter-pipeline.md](cookbook/ixp-filter-pipeline.md) | End-to-end IXP toolchain: arouteserver → `rs-config-render` → validated reload → Alice-LG looking glass |
| [cookbook/manrs-ixp-action1.md](cookbook/manrs-ixp-action1.md) | MANRS IXP Programme Action 1, mapped requirement-by-requirement to validated config and member-verifiable surfaces |
| [cookbook/paired-route-servers.md](cookbook/paired-route-servers.md) | Runbook: two independent route servers — staggered updates, inter-RS consistency diff, maintenance-window drain |
| [explain.md](explain.md) | Answer "why is this route (not) here?": the catalog of every explain surface, with the support-ticket workflow |
| [deployment.md](deployment.md) | End-to-end install + lifecycle: systemd, Docker, containerlab, validate, reload, upgrade |
| [ribdiff.md](ribdiff.md) | Drive `rbgp diff advertised` for the shadow trial (also the `rbgp-ribsnap/1` snapshot-format reference) |
| [evpn-vtep-setup.md](evpn-vtep-setup.md) | Prepare kernel netdev topology (bridge/VXLAN/VRF) for the EVPN VTEP dataplane |
| [evpn-vtep-troubleshooting.md](evpn-vtep-troubleshooting.md) | Runbook: debugging the bidirectional EVPN VTEP path, symptom by symptom |
| [evpn-alpha-soak.md](evpn-alpha-soak.md) | Checklist for running EVPN VTEP alpha confidence soaks |
| [GRAFANA.md](GRAFANA.md) | Import the overview dashboard and load the Prometheus alert-rule pack |
| [FUZZING.md](FUZZING.md) | Build and run the cargo-fuzz targets over every peer-fed decode surface |
| [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md) | Contributor: pre-publish smoke matrix for a tagged release |
| [config-knob-contributor-guide.md](config-knob-contributor-guide.md) | Contributor: everything a new config knob must ship with (reload class, persistence, docs, tests) |

## Reference — look something up

| Doc | What it describes |
|-----|-------------------|
| [CONFIGURATION.md](CONFIGURATION.md) | Every TOML config key, with examples |
| [rustbgpd.schema.json](rustbgpd.schema.json) | JSON Schema for the TOML config (editor integration; regenerated via `--dump-config-schema`) |
| [reload-matrix.md](reload-matrix.md) | Per-field reload classification: live, reload-applied, restart-required, rejected |
| [API.md](API.md) | gRPC API reference with examples for every RPC |
| [grpc-method-inventory.md](grpc-method-inventory.md) | Authorization tier of every gRPC method (machine-readable twin: [grpc-method-inventory.json](grpc-method-inventory.json)) |
| [rpol-language.md](rpol-language.md) | The `.rpol` typed policy language, ADR-0096 |
| [OPERATIONS.md](OPERATIONS.md) | Production reference: reload semantics, metrics catalog, failure modes, authorization audit (contains runbook-style debugging sections) |
| [GNMI.md](GNMI.md) | The supported gNMI / OpenConfig operational-state subset |
| [EMBEDDING.md](EMBEDDING.md) | The crate map for using rustbgpd's layers as Rust libraries |
| [SECURITY.md](SECURITY.md) | Security posture, deployment tiers, firewall guidance |
| [LIMITATIONS.md](LIMITATIONS.md) | Current product boundaries and known non-goals |
| [gobgp-parity.md](gobgp-parity.md) | Feature-by-feature parity table against GoBGP |
| [../crates/cli/README.md#familiar-command-map](../crates/cli/README.md#familiar-command-map) | Familiar command map: the FRR/BIRD show-command mental model translated to `rbgp` |
| [COMPARISON.md](COMPARISON.md) | Feature comparison across open-source BGP daemons |
| [ixp-evaluation.md](ixp-evaluation.md) | One-page IXP route-server evaluation matrix: capability status with the receipt or config behind each row |
| [kernel-dataplane-runner.md](kernel-dataplane-runner.md) | How the privileged Linux dataplane CI workflow runs |
| [grafana/](grafana/) | The importable Grafana dashboard JSON |

## Explanation — design, evidence, and history

| Doc | What it explains |
|-----|------------------|
| [DESIGN.md](DESIGN.md) | Architecture, tradeoffs, protocol scope, rationale |
| [adr/](adr/README.md) | Architecture Decision Records for every significant protocol and design choice |
| [USE_CASES.md](USE_CASES.md) | Deployment scenarios and their architecture (for step-by-step configs, see the cookbook) |
| [RFC_NOTES.md](RFC_NOTES.md) | Per-RFC conformance notes: interpretations, deviations, supported standards at a glance |
| [OPERATIONAL_PROOF.md](OPERATIONAL_PROOF.md) | Roll-up of operational evidence: interop, dataplane, scale, memory, soaks |
| [RECEIPTS.md](RECEIPTS.md) | Index of labs and measurements backing every wire-behavior and performance claim |
| [BENCHMARKS.md](BENCHMARKS.md) | Criterion micro-benchmarks and cross-stack perf snapshots |
| [INTEROP.md](INTEROP.md) | Interop validation results against FRR, GoBGP, BIRD, and vendor NOSes |
| [soaks/](soaks/) | Archived long-run soak postmortems (raw artifacts under [artifacts/](artifacts/)) |
| [perf/](perf/) | Scale receipts (1000-peer / VPN convergence measurements) |
| [evpn-enablement.md](evpn-enablement.md) | Gate-by-gate EVPN roadmap and its history |
| [milestones.md](milestones.md) | Archived build orders and exit criteria from initial development |
| [upstream-findings.md](upstream-findings.md) | Bugs and quirks found in peer software during interop development |
