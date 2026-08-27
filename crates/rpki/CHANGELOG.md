# Changelog

This changelog covers the independently published `rustbgpd-rpki` crate.
Daemon and workspace changes remain in the repository-level `CHANGELOG.md`.

## Unreleased

## 0.1.0 - 2026-08-27

- Initial independent crate release with immutable VRP and ASPA tables, RFC
  6811 origin validation, role-aware ASPA path verification, a bounded RTR
  client, and multi-cache snapshot management.
- Established the `0.1.x` public boundary across both the crate-root facade and
  the public module paths, including the raw RTR PDU codec. Breaking Rust API
  or incompatible public wire-type changes require `0.2.0`.
- Documented the Tokio runtime boundary, direct dependency set, plain-TCP RTR
  transport, supported RFC/draft scope, and the separation between standalone
  validation capabilities and rustbgpd daemon integration.
