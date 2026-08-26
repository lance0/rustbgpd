# Changelog

This changelog covers the independently published `rustbgpd-fsm` crate. Daemon
and workspace changes remain in the repository-level `CHANGELOG.md`.

## Unreleased

## 0.5.0 - 2026-08-26

- **Additive FSM API:** Added `Event::BfdDown`. A BFD-triggered teardown in
  `OpenSent`, `OpenConfirm`, or `Established` emits the typed Cease notification
  and authoritative session-down cleanup; earlier connection states return to
  `Idle` without a notification.
- **Adoption example:** Added a socket-free walkthrough that uses only public
  APIs to drive `Idle` through `Established`, print returned `Action` values,
  and verify the negotiated peer identity, hold time, and address family.

## 0.4.1 - 2026-08-19

- **Additive FSM API:** Added `Session::negotiated_shared`, which returns shared
  ownership of the negotiated session parameters. The existing borrowed
  `Session::negotiated` accessor is unchanged.
- Updated the dependency boundary to `rustbgpd-wire` 0.17.1 without removing or
  changing an existing direct FSM API.

## 0.4.0 - 2026-08-08

- **Dependency-only breaking change:** Updated the public wire-type boundary
  from `rustbgpd-wire` 0.16 to 0.17. The incompatible 0.x dependency update
  changes the identity of the wire types exposed through the FSM API; the FSM
  itself made no direct API change in this release.
- The paired `rustbgpd-wire` 0.17 release separately made
  `encode_evpn_nlri` fallible. Direct wire callers must handle its `Result`;
  that encoder change is not what changes the FSM's exposed type identities.

## 0.3.1 - 2026-07-27

- **Additive FSM API:** Added `PeerConfig::min_hold_time` and
  `PeerConfig::required_families` behind the existing `#[non_exhaustive]`
  construction boundary.
- Negotiation now honors the last duplicate Graceful Restart capability and
  rejects invalid OPEN identities, including AS 0 and a local router ID reused
  by an iBGP peer.
- Updated the dependency boundary to `rustbgpd-wire` 0.16 without removing or
  changing an existing direct FSM API.

## 0.3.0 - 2026-07-18

- **Direct FSM match-boundary change:** Marked `TimerType` and `FsmError`
  `#[non_exhaustive]`; downstream matches must include a wildcard arm.
- Added experimental family-local Paths-Limit negotiation state and the
  `graceful_restart_preserves_family` helper.
- **Dependency breaking change:** Updated the exposed wire-type boundary to the
  incompatible `rustbgpd-wire` 0.15 line.

## 0.2.0 - 2026-07-06

- **Direct breaking FSM API:** Added a `hold_time` argument to
  `default_send_hold_time`; `PeerConfig` gained `send_hold_time`.
- **Dependency breaking change:** Updated the exposed wire-type boundary from
  `rustbgpd-wire` 0.13 to 0.14.

## 0.1.0 - 2026-06-30

- Initial independent crate release of the six-state RFC 4271 FSM, with timers
  modeled as input `Event` values and output `Action` values and with OPEN
  validation and capability negotiation.
- Established the forward-compatible construction and matching boundary:
  `PeerConfig`, `Event`, `Action`, and `NegotiatedSession` are
  `#[non_exhaustive]`; `PeerConfig::new` and `Default` construct configurations;
  the fixed six-state `SessionState` remains exhaustively matchable.
