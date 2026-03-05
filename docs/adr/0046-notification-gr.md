# ADR-0046: Notification GR (RFC 8538)

- **Status:** Accepted
- **Date:** 2026-03-05

## Context

RFC 8538 "Notification Message Support for BGP Graceful Restart" extends the Graceful Restart mechanism so that NOTIFICATION messages can trigger GR route preservation instead of an immediate hard reset. It adds:

1. **N-bit** (bit 14, 0x4000) in the GR capability flags — signals support for Notification GR.
2. **Cease/Hard Reset** (subcode 9) — an explicit escape hatch to bypass GR when a hard teardown is intended.

Without RFC 8538, receiving a NOTIFICATION always means "hard reset, purge routes." With it, NOTIFICATIONs trigger GR (route preservation) unless the specific Cease/Hard Reset subcode is used. This completes the GR story alongside ADR-0024 (helper mode), ADR-0040 (restarting speaker), and ADR-0042 (LLGR).

## Decision

### N-bit in GR Capability

The GR capability (code 64) flags field layout:
- Bit 15 (0x8000): R-bit (restart state) — existing
- Bit 14 (0x4000): N-bit (notification GR) — new
- Bits 0-11 (0x0FFF): restart time — existing

`notification: bool` field added to `Capability::GracefulRestart` variant. Always advertised as `true` when GR is enabled — unconditional, like Enhanced Route Refresh.

### Negotiation

`peer_notification_gr: bool` on `NegotiatedSession`. True when:
- peer advertised GR capability
- peer set N-bit
- local GR is enabled

### Hard Reset Tracking

Two per-session booleans on `PeerSession`:
- `received_hard_reset` — set when peer sends Cease/Hard Reset (subcode 9)
- `sent_hard_reset` — set when we send Cease/Hard Reset

Both reset on SessionDown cleanup (per-session, not persistent).

### GR Decision Logic

The SessionDown GR decision now checks whether teardown was caused by
NOTIFICATION semantics:

- non-NOTIFICATION teardown (e.g., TCP reset): legacy GR behavior
- NOTIFICATION-triggered teardown: requires negotiated `peer_notification_gr`
- Cease/Hard Reset: always bypasses GR

Effective guard:

```rust
if neg.peer_gr_capable
    && self.config.peer.graceful_restart
    && (!self.notification_teardown || neg.peer_notification_gr)
    && !self.received_hard_reset
    && !self.sent_hard_reset
```

If either hard reset flag is set, the session falls through to `PeerDown` (routes purged immediately) instead of `PeerGracefulRestart`.

### No New Config

N-bit advertisement is unconditional. Hard Reset sending is not automated in this change — it's primarily a reactive feature (honoring peer's Hard Reset). Future work could add a `hard_reset` flag to the `DisablePeer` gRPC command.

## Consequences

- Peers that support RFC 8538 will see the N-bit in our GR capability.
- Cease/Hard Reset from a peer now correctly bypasses GR, preventing stale route preservation when the peer explicitly requests a hard teardown.
- No new configuration knobs or gRPC fields.
- The `HARD_RESET` constant (Cease subcode 9) was already defined in the wire crate.
- Backward compatible: peers without N-bit support ignore the bit per RFC.
