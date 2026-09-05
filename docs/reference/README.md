# Reference

> **Document class: CURRENT.** This maintained page reflects the project as it is now; dated sections remain bounded to their stated scope.

Look up commands, configuration, and compatibility boundaries.

[All documentation](../README.md)

- [Configuration](configuration.md) — TOML fields and examples.
- [Configuration schema](rustbgpd.schema.json) — Machine-readable schema for editor integration.
- [Reload matrix](reload-matrix.md) — When each configuration change takes effect.
- [Operations](operations.md) — Reload semantics, metrics, failure modes, and audit events.
- [gRPC API](api.md) — Services, RPCs, and request examples.
- [gRPC authorization inventory](grpc-method-inventory.md) — Method tiers and their authorization classification.
- [gRPC inventory JSON](grpc-method-inventory.json) — Machine-readable authorization inventory.
- [gNMI and OpenConfig](gnmi.md) — Supported telemetry paths and operations.
- [Policy language](rpol-language.md) — The typed routing-policy language and its tools.
- [Rust libraries](embedding.md) — Workspace crates and their embedding boundaries.
- [Security posture](security.md) — Management API protection and deployment tiers.
- [Limitations](limitations.md) — Current product boundaries and unsupported behavior.
- [Known issues](known-issues.md) — Known defects, workarounds, and operational caveats.
- [Stability and compatibility](stability.md) — Daemon, library, adapter, and authorization contracts.
- [Narrow v1 contract](v1-stable-contract.md) — The route-server and route-reflector compatibility promise.
- [Stable surface inventory](v1-stable-surface.json) — Machine-readable inventory of the narrow v1 contract.
- [Format and version namespaces](format-version-namespaces.md) — Independent versions for stored and exchanged formats.
- [RFC implementation notes](rfc-notes.md) — Protocol interpretations and deviations.
- [ASPA conformance](aspa-conformance.md) — Verification procedures and route-server scope.
- [Path-attribute registry](path-attribute-registry.md) — Implementation, propagation, and evidence by attribute.
