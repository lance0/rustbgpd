# rustbgpd documentation

> **Document class: CURRENT.** This maintained page reflects the project as it is now; dated sections remain bounded to their stated scope.

Find the guide, reference, or evidence for the task at hand.

## Contents

[Tutorials](#tutorials) · [How-to](#how-to) · [Reference](#reference) · [Explanation](#explanation) · [Evidence](#evidence) · [Project](#project)

## Tutorials

Learn by running a small example.

| Page | Scope |
|------|-------|
| [Quickstart](tutorials/quickstart.md) | Start a daemon, establish a session, and use the CLI. |
| [Operator labs](tutorials/operator-labs.md) | Introduce a local policy fault, explain the rejected routes, and recover. |
| [Docker Compose demo](../examples/docker-compose/README.md) | Run rustbgpd and an FRR peer together. |
| [EVPN leaf example](../examples/evpn-vtep-leaf/README.md) | Follow a leaf-mode configuration walkthrough. |

## How-to

Follow a procedure for a specific task.

| Page | Scope |
|------|-------|
| [Deployment](how-to/deployment.md) | Install, validate, reload, and upgrade a daemon. |
| [Explain route decisions](how-to/explain.md) | Find why a route was selected, rejected, or advertised. |
| [Compare advertised routes](how-to/ribdiff.md) | Compare a shadow route server with the incumbent. |
| [Settlement watchdog](how-to/settlement-watchdog.md) | Recover when configuration settlement cannot be proved. |
| [EVPN VTEP setup](how-to/evpn-vtep-setup.md) | Prepare bridge, VXLAN, and VRF interfaces. |
| [EVPN VTEP troubleshooting](how-to/evpn-vtep-troubleshooting.md) | Diagnose the bidirectional VTEP dataplane. |
| [EVPN alpha-soak checklist](how-to/evpn-alpha-soak.md) | Run the VTEP confidence checks. |
| [Grafana and alerting](how-to/grafana.md) | Import dashboards and load Prometheus alert rules. |
| [Kernel dataplane runner](how-to/kernel-dataplane-runner.md) | Run the privileged Linux dataplane checks. |
| [Fuzzing](how-to/fuzzing.md) | Build and run the parser fuzz targets. |
| [Add a configuration field](how-to/config-knob-contributor-guide.md) | Cover validation, reload, persistence, and documentation. |
| [Answer route questions from an AI agent](how-to/mcp-server.md) | Expose the explain surfaces to an MCP host, read-only. |
| [Scenario cookbook](cookbook/README.md) | Choose a complete deployment recipe. |
| [iBGP route reflector](cookbook/route-reflector.md) | Deploy a route reflector for an iBGP client fleet. |
| [L3VPN route reflector](cookbook/l3vpn-route-reflector.md) | Reflect VPN routes with RT-Constrain filtering. |
| [IXP route server](cookbook/route-server.md) | Configure members and policy by hand. |
| [IXP filter pipeline](cookbook/ixp-filter-pipeline.md) | Keep an ARouteServer configuration workflow. |
| [IXP Manager route server](cookbook/ixp-manager-route-server.md) | Provision from IXP Manager and manage activation. |
| [Route-server shadow pilot](cookbook/route-server-shadow-pilot.md) | Evaluate beside an incumbent without taking authority. |
| [Route-server migration](cookbook/route-server-migration.md) | Plan a shadow trial, cutover, and rollback. |
| [MANRS IXP Action 1](cookbook/manrs-ixp-action1.md) | Map the requirements to configuration and verification. |
| [Controller and monitoring feed](cookbook/monitoring-feed.md) | Export BMP, durable events, and MRT. |
| [EVPN fabric route reflector](cookbook/evpn-fabric-rr.md) | Reflect EVPN routes in a leaf/spine fabric. |
| [Policy quickstart](cookbook/policy-quickstart.md) | Test and activate a typed routing policy. |
| [Peer-flap triage](cookbook/peer-flap-triage.md) | Find and contain a recurring session failure. |
| [Route-reflector pair operations](cookbook/rr-pair-day2.md) | Maintain a redundant pair through routine changes. |
| [Paired route servers](cookbook/paired-route-servers.md) | Stage updates, compare output, and drain for maintenance. |
| [Activation manual recovery](cookbook/activation-manual-recovery.md) | Resolve an interrupted activation or lifecycle operation. |

## Reference

Look up commands, configuration, and compatibility boundaries.

| Page | Scope |
|------|-------|
| [Configuration](reference/configuration.md) | TOML fields and examples. |
| [Configuration schema](reference/rustbgpd.schema.json) | Machine-readable schema for editor integration. |
| [Reload matrix](reference/reload-matrix.md) | When each configuration change takes effect. |
| [Operations](reference/operations.md) | Reload semantics, metrics, failure modes, and audit events. |
| [gRPC API](reference/api.md) | Services, RPCs, and request examples. |
| [gRPC authorization inventory](reference/grpc-method-inventory.md) | Method tiers and their authorization classification. |
| [gRPC inventory JSON](reference/grpc-method-inventory.json) | Machine-readable authorization inventory. |
| [gNMI and OpenConfig](reference/gnmi.md) | Supported telemetry paths and operations. |
| [Policy language](reference/rpol-language.md) | The typed routing-policy language and its tools. |
| [Rust libraries](reference/embedding.md) | Workspace crates and their embedding boundaries. |
| [Security posture](reference/security.md) | Management API protection and deployment tiers. |
| [Limitations](reference/limitations.md) | Current product boundaries and unsupported behavior. |
| [Known issues](reference/known-issues.md) | Known defects, workarounds, and operational caveats. |
| [Stability and compatibility](reference/stability.md) | Daemon, library, adapter, and authorization contracts. |
| [Narrow v1 contract](reference/v1-stable-contract.md) | The route-server and route-reflector compatibility promise. |
| [Stable surface inventory](reference/v1-stable-surface.json) | Machine-readable inventory of the narrow v1 contract. |
| [Format and version namespaces](reference/format-version-namespaces.md) | Independent versions for stored and exchanged formats. |
| [RFC implementation notes](reference/rfc-notes.md) | Protocol interpretations and deviations. |
| [ASPA conformance](reference/aspa-conformance.md) | Verification procedures and route-server scope. |
| [Path-attribute registry](reference/path-attribute-registry.md) | Implementation, propagation, and evidence by attribute. |
| [Familiar command map](../crates/cli/README.md#familiar-command-map) | Translate FRR and BIRD commands to the CLI. |

## Explanation

Understand the design and choose a deployment role.

| Page | Scope |
|------|-------|
| [Feature tour](explanation/feature-tour.md) | Capabilities behind the repository overview. |
| [Use cases](explanation/use-cases.md) | Deployment roles and their architecture. |
| [Architecture](explanation/architecture.md) | Workspace structure and subsystem boundaries. |
| [Design](explanation/design.md) | Constraints, tradeoffs, and protocol scope. |
| [Implementation comparison](explanation/comparison.md) | Capability and scope comparisons with other BGP daemons. |
| [GoBGP parity](explanation/gobgp-parity.md) | Detailed capability comparison against the pinned release. |
| [IXP evaluation](explanation/ixp-evaluation.md) | Assess route-server fit using configuration and evidence. |

## Evidence

Inspect the receipts behind protocol, performance, and operational claims.

| Page | Scope |
|------|-------|
| [Receipts index](receipts.md) | Find the lab or measurement behind a claim. |
| [Operational proof](operational-proof.md) | Review the operational evidence across subsystems. |
| [Interoperability](interop.md) | Validation against real BGP peers and network operating systems. |
| [Benchmarks](benchmarks.md) | Microbenchmarks and their measured scope. |
| [Performance archive](perf/README.md) | Dated performance receipts and their supporting artifacts. |
| [Soak archive](soaks/README.md) | Long-running test reports, acceptance gates, and receipt templates. |
| [Raw artifacts](artifacts/) | Preserved data supporting published findings. |

## Project

Follow development plans, contribution guidance, and release history.

| Page | Scope |
|------|-------|
| [Roadmap](project/roadmap.md) | Current development direction and remaining work. |
| [EVPN enablement](project/evpn-enablement.md) | The staged EVPN plan and its completion evidence. |
| [Release checklist](project/release-checklist.md) | Required checks for publishing a release. |
| [Contributing](../CONTRIBUTING.md) | Build, test, and submit a change. |
| [Support](../SUPPORT.md) | Get help and check platform support. |
| [Report a vulnerability](../SECURITY.md) | Report a security issue privately. |
| [Changelog](../CHANGELOG.md) | Unreleased changes and the current release. |
| [Older releases](project/changelog/older-releases.md) | Archived release notes. |
| [Roadmap history](project/roadmap-history.md) | Completed development phases. |
| [Milestone history](project/milestones.md) | Archived build orders and exit criteria. |
| [Upstream findings](project/upstream-findings.md) | Dated observations from interoperability testing. |
| [Architecture decisions](adr/README.md) | Recorded decisions and their original context. |

## Document classes

**CURRENT** pages describe the maintained system; **REFERENCE** pages define a contract, specification, or reusable procedure; **HISTORICAL** pages preserve a dated decision or observation.

Historical records retain their original scope. Archive indexes guide readers to individual receipts, decisions, and supporting artifacts.
