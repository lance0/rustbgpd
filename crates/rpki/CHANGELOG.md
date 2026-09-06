# Changelog

This changelog covers the independently versioned `rustbgpd-rpki` crate.
Daemon and workspace changes remain in the repository-level `CHANGELOG.md`.

## 0.2.0 - Unreleased

- Prepared the wire dependency move to `0.20.0`. Public signatures expose
  wire types, so embedders sharing them must upgrade both dependencies to the
  corresponding compatibility line.

- Added `RtrClient::with_dialer` so embedders can supply custom cache connection setup.

## 0.1.0 - 2026-08-30

- Added an optional cache-inventory attachment with separate enhanced-update
  and bounded query handles. Existing `VrpUpdate`, `RtrClient::new`, and
  `VrpManager::new` callers remain source-compatible; attached clients publish
  contribution and accepted RTR epoch metadata atomically.

- Added `VrpTable::covering_vrps` and the `CoveringVrp` / `CoveringVrps`
  result types. The helper walks only ancestor buckets, returns authorizers
  first, applies a 256-row hard cap with exact omission, and exposes the
  table's effective duplicate-collapsed VRPs without changing `validate`.
- First independent crate release with immutable VRP and ASPA tables, RFC 6811
  origin validation, role-aware ASPA path verification, a bounded RTR client,
  and multi-cache snapshot management. Its public wire-type boundary starts on
  `rustbgpd-wire 0.19.0`; there is no earlier RPKI compatibility line.
- Established the `0.1.x` public boundary across both the crate-root facade and
  the public module paths, including the raw RTR PDU codec. Breaking Rust API
  or incompatible public wire-type changes require `0.2.0`.
- Documented the Tokio runtime boundary, direct dependency set, plain-TCP RTR
  transport, supported RFC/draft scope, and the separation between standalone
  validation capabilities and rustbgpd daemon integration.
