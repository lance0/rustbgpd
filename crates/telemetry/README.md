# rustbgpd-telemetry

Prometheus metrics and structured tracing for rustbgpd.

Part of [rustbgpd](https://github.com/lance0/rustbgpd).

## Metrics

Exposes a `prometheus` HTTP endpoint with gauges and counters covering:

- Peer state (established/down counts)
- RIB sizes (Adj-RIB-In, Loc-RIB, Adj-RIB-Out per family)
- UPDATE processing (received, sent, errors)
- Graceful restart (active peers, stale routes, timer expirations)
- RPKI (VRP count, validation outcomes)
- FlowSpec (rule counts per family)

## Logging

Structured JSON logging via `tracing` + `tracing-subscriber` with
environment-based filter control (`RUST_LOG`).

## License

MIT OR Apache-2.0
