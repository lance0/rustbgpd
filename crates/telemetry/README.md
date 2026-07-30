# rustbgpd-telemetry

Prometheus metrics and structured tracing for rustbgpd.

Part of [rustbgpd](https://github.com/lance0/rustbgpd).

## Metrics

Provides the Prometheus metrics registry (`BgpMetrics`) served by the
daemon's metrics HTTP endpoint, with gauges and counters covering peer
state, RIB sizes, UPDATE processing, policy, graceful restart, RPKI,
FlowSpec, BFD, BMP, EVPN, update-group, dynamic-neighbor admission,
and outbound-prefix-limit state — see
[docs/OPERATIONS.md](../../docs/OPERATIONS.md) for the operator-facing
metrics coverage.

## Logging

Structured JSON logging via `tracing` + `tracing-subscriber` with
environment-based filter control (`RUST_LOG`).

## License

MIT OR Apache-2.0
