# rustbgpd-telemetry

Prometheus metrics and structured tracing for rustbgpd.

Part of [rustbgpd](https://github.com/lance0/rustbgpd).

## Metrics

Provides the Prometheus metrics registry (`BgpMetrics`) served by the
daemon's metrics HTTP endpoint, with gauges and counters covering peer
state, RIB sizes, UPDATE processing, policy, graceful restart, RPKI,
FlowSpec, BFD, BMP, EVPN, update-group, dynamic-neighbor admission,
outbound-prefix-limit, and conditional-advertisement state — see
[docs/reference/operations.md](../../docs/reference/operations.md) for the operator-facing
metrics coverage.

## Logging

Logging via `tracing` + `tracing-subscriber`: structured JSON lines, or
human-readable text when `init_logging` is called with `json = false`
(the daemon's `log_format = "text"`), with environment-based filter
control (`RUST_LOG`).

## License

MIT OR Apache-2.0
