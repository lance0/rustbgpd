# Changelog

This changelog covers the independently versioned `rustbgpd-rpki` crate.
Daemon and workspace changes remain in the repository-level `CHANGELOG.md`.

## 0.10.0 - 2026-11-08

- Recheck the held data expiry while applying buffered RTR PDUs. An End of
  Data processed at or after the captured expiry ends the transaction and
  flushes that cache's VRPs and ASPAs instead of renewing expired data.
  Both incremental and full responses use the existing expiry path.

- Decode the RTR Router Key PDU (type 9, RFC 8210 §5.10) into the new
  `RtrPdu::RouterKey` variant, and encode it. The client ignores it, because
  it does not validate BGPsec paths. Previously the codec rejected type 9 as an
  Unsupported PDU Type, so a cache serving BGPsec router keys (StayRTR does by
  default) failed every transaction that carried one, and the client never
  accepted that cache's VRPs or ASPAs. Framing is checked: the PDU must hold
  the 20-octet SKI and AS number, and the SubjectPublicKeyInfo's DER length
  must fill the rest exactly. `RtrPdu` is already `#[non_exhaustive]`, so the
  new variant is additive.
- Bound the RPKI records an `RtrClient` holds. `RtrClient::with_record_limits`
  takes a per-cache cap and a shared `RecordBudget`. Records (VRPs plus ASPA
  provider ASNs) are charged while a transaction is decoded. A transaction that
  would exceed either cap ends the session with the new
  `RtrError::RecordLimit`, publishes nothing, and keeps the cache's last
  accepted data. The next query is a Reset Query. With
  `RtrClient::with_cache_inventory`, the charge travels with each accepted
  update: it stays charged while the update waits for `VrpManager`, and the
  manager releases it when that cache's data is replaced or removed. Without
  the inventory attachment, the client keeps the charge for its last accepted
  data, so a consumer of the plain `VrpUpdate` channel that queues updates is
  not covered. Withdrawals are charged against the total budget while their
  delta is staged or queued, and released once the manager applies it; they do
  not count against the per-cache cap.
- A full table's withdrawal lists are freed before their charge is released.
  Previously they stayed allocated, uncounted, while the update waited for a
  full `VrpManager` queue. `RpkiTableUpdate` and `AspaTableUpdate` snapshots
  are merged copies and are not charged: a consumer that queues them should
  keep its queue short or coalesce superseded snapshots.
- A second Cache Response inside one RTR response now ends the transaction as
  a protocol violation. Previously it restarted collection, and nothing staged
  before it was published.
- **Behavior change:** without `with_record_limits`, a client uses
  `DEFAULT_MAX_CACHE_RECORDS` (4000000) and its own `DEFAULT_MAX_TOTAL_RECORDS`
  (10000000) budget. Previously the only limit was the per-transaction record
  budget, which reset with every serial update.
- The new API is additive, and `RtrError` was already `#[non_exhaustive]`.
- `VrpManager` keys each cache's VRPs by the canonical prefix, with host bits
  cleared, as validation already does. RTR v1 accepts Prefix PDUs with host
  bits set. A withdrawal sent in canonical form could miss its host-bit
  announcement and leave that VRP authorizing the prefix, and one VRP sent both
  ways counted twice.
- A cache that answers the v2 query at a lower version during §7 negotiation is
  no longer sent a fatal Error Report code 8. That code is for a version that
  differs from a negotiated one. The client now closes the connection and
  reconnects at the lower version, as 8210bis §7 allows.
- Enforce the RTR expire interval (RFC 8210 §6) while a query is in flight and
  while a reconnect is connecting. Previously the expiry was checked only while
  the session sat idle and between retries, so a cache that accepted a query and
  stalled kept expired data published until the 5-minute transaction deadline,
  and a hung connect kept it indefinitely. The bound covers query writes as
  well as reads, so a cache that stops reading cannot hold a query write, and
  the expired data, past the deadline.
- A v1 session that the client fell back to from v2 now reconnects to probe
  v2 again at its first refresh at least an hour after the fallback (8210bis
  §7: each session opens at the highest version, and the version changes only
  on a new connection). Previously any failure before the first End of Data,
  such as one connection reset, kept the cache at v1, without ASPA, for the
  life of the process. A probe the cache refuses falls back to v1 at once and
  keeps the held v1 data and serial. Only a closed connection or a lower
  version byte before the cache answers counts as a refusal, besides error
  code 4. A PDU at the probed version that fails to decode, such as a corrupt
  Prefix PDU, shows the cache speaks that version: it ends the session under
  its own §12 handling, flushing the held data where that applies, before or
  after the Cache Response.
- Move to wire `0.28.0` for IPv4/IPv6 VPN FlowSpec (`Safi::FlowSpecVpn` and
  the new `MpReachNlri`/`MpUnreachNlri` fields). Upgrade wire 0.28, FSM 0.15
  and RPKI 0.10 together.

## 0.9.0 - 2026-11-01

- Move to wire `0.27.0` for the direct target-IP FlowSpec actions and typed,
  lossless IPv6 extended communities (attribute 25). There is no independent
  verifier or RTR change. Upgrade crates exchanging public wire types together:
  wire 0.27, FSM 0.14 and RPKI 0.9.

## 0.8.1 - 2026-10-24

- Documentation only: document the cache inventory contract
  (`CacheInventoryAttachment`, `CacheQueryHandle`, `CacheState`,
  `AcceptedCacheState`, `CacheList`, `MAX_CACHE_ROWS`), including that
  `CacheQueryHandle::list` has no internal timeout and that query senders
  alone do not keep the manager running, and the ASPA record and verdict
  fields (`AspaRecord`, `AspaInvalidHop`, `AspaVerificationResult`). Warn on
  undocumented public items (`#![warn(missing_docs)]`). No public item,
  signature or verifier/RTR behavior changes.

## 0.8.0 - 2026-10-18

- Move the public wire dependency to 0.26. Verifier and RTR behavior and
  method signatures are unchanged. Upgrade wire/FSM/RPKI together.

## 0.7.0 - 2026-10-12

- Move the public wire dependency to 0.25. Verifier and RTR behavior and
  method signatures are unchanged. Upgrade wire/FSM/RPKI together.

## 0.6.0 - 2026-10-11

- Move the public wire dependency to 0.24. Existing verifier and RTR behavior
  and method signatures are unchanged. Upgrade wire/FSM/RPKI together.
- Add `VrpManager::with_end_of_data_observer`, called with a configured
  cache's address and `Some(instant)` after each accepted End of Data, the
  monotonic instant `AcceptedCacheState::age_seconds` counts from, or `None`
  when a flush or expiry drops the retained contribution. An ordinary
  disconnect does not call it. Additive; existing observers are unchanged.

## 0.5.0 - 2026-10-03

- Move the public wire dependency to 0.23 for typed Type 6 SMET support.
  Upgrade crates exchanging public wire types together. No additional
  RPKI verification or RTR behavior changes.

## 0.4.0 - 2026-09-27

- Move the public wire dependency to 0.22. Upgrade dependencies that
  exchange wire types together; verifier and RTR method signatures are
  unchanged.

- Documented `RtrClientConfig::max_expire_interval` when unset: it adds no
  ceiling of its own, so the configured expire interval is limited only by
  the RFC 8210 section 6 bounds and a cache-advertised value only by the
  protocol ceiling. The previous wording said the configured interval was left
  unchanged. No public item or runtime behavior changed.

## 0.3.2 - 2026-09-23

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
- Add `VrpManager::with_connectivity_observer`, called with a configured
  cache's address and `true` or `false` when its RTR session goes up or
  down. It is independent of the readiness observer: an ordinary disconnect
  retains the cache's contribution until expiry, while a flush drops it at
  once.
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
