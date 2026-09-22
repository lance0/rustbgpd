# Changelog

This changelog covers the independently versioned `rustbgpd-rpki` crate.
Daemon and workspace changes remain in the repository-level `CHANGELOG.md`.

## 0.3.2 - Unreleased

- `RtrClient::new` now clamps a `RtrClientConfig::retry_interval` above
  the RFC 8210 §6 maximum of 7200 seconds down to 7200 seconds and logs a
  warning. Retry paces reconnects before any End of Data can lower it, so
  a larger value parked the first reconnect at tokio's far-future deadline
  and the client never retried a cache that was down at startup. Values
  from 1 to 7200 seconds are unchanged. The configured-timer warning now
  reports the applied value as `bounded` (previously `raised`) with the
  message "RTR configured timer outside the §6 range, bounded".
- Publish the first accepted empty VRP and ASPA tables so operator queries
  distinguish authoritative empty data from unavailable data. Identical
  replays remain suppressed; disconnects before any acceptance remain unavailable.
- Add `AspaTable::providers`, a borrowed sorted merged-provider lookup that
  distinguishes an absent customer from a present empty set and preserves AS0.
- Add `aspa_verify::validation_context` to derive the local-role first-AS
  exemption consistently from an explicit neighbor ASN. Verification behavior
  and existing context fields remain unchanged.

## 0.3.1 - 2026-09-18

- `RtrClient::new` now raises a `RtrClientConfig::refresh_interval` or
  `retry_interval` below the RFC 8210 §6 minimum of 1 second to 1 second
  and logs a warning. A zero value previously polled the cache or
  reconnected with no delay between attempts. Values of 1 second or more
  are unchanged.
- `RtrClient::new` now bounds `RtrClientConfig::expire_interval` and a
  `Some` `max_expire_interval` to the RFC 8210 §6 range with a warning:
  zero is raised to 600 seconds and a value above 172800 seconds is
  clamped down to it. A zero previously armed expiry at the End of Data
  instant whenever the cache omitted its expire (`Some(0)` on every End of
  Data), flushing the table just fetched and reconnecting once a second,
  and a value near `u64::MAX` overflowed the expiry deadline. Non-zero
  values up to two days, including values below 600 seconds, are unchanged.

## 0.3.0 - 2026-09-13

- Prepared the wire dependency move to `0.21.0`. Public signatures expose
  wire types, so embedders exchanging those types must upgrade to the
  corresponding compatibility line together.
- Marked `RtrPdu`, `RtrDecodeError`, `RtrEncodeError`, and `RtrError`
  non-exhaustive. Downstream exhaustive matches now require a fallback;
  existing variant constructors and fields are unchanged. `ProviderAuth` and
  `VrpUpdate` remain exhaustive. No variants or runtime behavior changed.

## 0.2.0 - 2026-09-07

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
