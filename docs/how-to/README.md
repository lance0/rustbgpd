# How-to

> **Document class: CURRENT.** This maintained page reflects the project as it is now; dated sections remain bounded to their stated scope.

Follow a procedure for a specific task.

[All documentation](../README.md)

- [Deployment](deployment.md) — Install, validate, reload, and upgrade a daemon.
- [Explain route decisions](explain.md) — Find why a route was selected, rejected, or advertised.
- [Compare advertised routes](ribdiff.md) — Compare a shadow route server with the incumbent.
- [Settlement watchdog](settlement-watchdog.md) — Recover when configuration settlement cannot be proved.
- [EVPN VTEP setup](evpn-vtep-setup.md) — Prepare bridge, VXLAN, and VRF interfaces.
- [EVPN VTEP troubleshooting](evpn-vtep-troubleshooting.md) — Diagnose the bidirectional VTEP dataplane.
- [EVPN alpha-soak checklist](evpn-alpha-soak.md) — Run the VTEP confidence checks.
- [Grafana and alerting](grafana.md) — Import dashboards and load Prometheus alert rules.
- [Kernel dataplane runner](kernel-dataplane-runner.md) — Run the privileged Linux dataplane checks.
- [Fuzzing](fuzzing.md) — Build and run the parser fuzz targets.
- [Add a configuration field](config-knob-contributor-guide.md) — Cover validation, reload, persistence, and documentation.
- [Answer route questions from an AI agent](mcp-server.md) — Expose the explain surfaces to an MCP host, read-only.

For complete deployment recipes, browse the [scenario cookbook](../cookbook/README.md).
