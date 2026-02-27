# ADR-0007: Explicit Prometheus registry, not global default

**Status:** Accepted
**Date:** 2026-02-27

## Context

The `prometheus` crate provides a global default registry via
`prometheus::default_registry()` and `register!` macros. An alternative
is to create an explicit `Registry` instance that the application owns
and passes around.

The telemetry crate needs to register ~8 metrics (counters, gauges) and
expose them for Prometheus scraping. The choice affects testability,
composability, and API ergonomics.

## Decision

`BgpMetrics::new()` creates a fresh `prometheus::Registry` and registers
all metrics against it. Callers access the registry via
`metrics.registry()` for gathering and exposition.

A `with_registry(registry)` constructor is provided for cases where the
caller wants to share a registry across components.

## Consequences

- **Positive:** Each test gets an isolated registry — no global state
  leaks between tests, no "metric already registered" panics.
- **Positive:** Multiple `BgpMetrics` instances can coexist (useful for
  testing, or if the daemon ever needs per-subsystem registries).
- **Positive:** The caller controls metric lifetime and exposition
  endpoint, not the library.
- **Negative:** Callers must thread `BgpMetrics` (or its registry) to
  wherever metrics need to be gathered. Acceptable — we already pass
  config and session state explicitly.
