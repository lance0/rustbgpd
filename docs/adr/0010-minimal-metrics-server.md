# ADR-0010: Minimal TCP Metrics Server, No HTTP Framework

**Status:** Accepted
**Date:** 2026-02-27

## Context

The daemon needs to expose a Prometheus `/metrics` endpoint for scraping.
The root crate already depends on `tokio` with `full` features and
`prometheus` for metric types. Adding an HTTP framework (hyper, axum,
warp) would introduce significant dependency weight for a single
endpoint that only needs to serve `GET /metrics` with `text/plain`.

## Decision

Use `tokio::net::TcpListener` directly with a hand-rolled HTTP response.
The server accepts connections, encodes the Prometheus registry via
`TextEncoder`, and writes a minimal HTTP/1.1 200 response with
`Content-Type: text/plain; version=0.0.4`. No request parsing, no
routing, no content negotiation.

## Consequences

**Positive:**
- Zero new dependencies. The metrics endpoint adds no crate weight.
- Simple to understand and audit — under 50 lines.
- Adequate for Prometheus scraping, which only needs `GET /metrics`.

**Negative:**
- Does not handle malformed HTTP requests gracefully (always returns 200).
- No support for `HEAD`, content negotiation, or HTTP/2.
- If the API crate later adds an HTTP server (e.g., for health checks),
  the metrics endpoint should migrate to that server to avoid binding
  two ports.

**Neutral:**
- The endpoint is a single `tokio::spawn` — easy to replace later
  without touching any other code.
