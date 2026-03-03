# ADR-0032: Extended Messages (RFC 8654)

**Status:** Accepted
**Date:** 2026-03-02

## Context

The BGP protocol limits messages to 4096 bytes (RFC 4271). With large
community lists, many path attributes, or Add-Path NLRI carrying multiple
paths, UPDATEs can exceed this limit. RFC 8654 defines the Extended
Message capability (code 6) to raise the maximum to 65535 bytes.

## Decision

### Capability

`Capability::ExtendedMessage` variant with no fields. Capability code 6,
length 0. Advertised unconditionally in OPEN (same pattern as Route
Refresh). Negotiated only when both sides advertise it.

### Wire codec

`BgpHeader::decode()` and `peek_message_length()` accept a
`max_message_len: u16` parameter. Validation checks
`!(MIN_MESSAGE_LEN..=max_message_len).contains(&length)`.
`decode_message()` passes the parameter through the decode chain.

### Transport

`ReadBuffer` gains a `max_message_len: u16` field (default 4096). When
the session is established and the peer advertised ExtendedMessage,
`set_max_message_len(65535)` is called, which reserves additional buffer
capacity.

`NegotiatedSession` carries `peer_extended_message: bool`. The session
stores `max_message_len` for outbound encode and passes it to
`send_message()` and `send_route_update()`.

### Constants

- `capability_code::EXTENDED_MESSAGE = 6`
- `EXTENDED_MAX_MESSAGE_LEN: u16 = 65535`

## Consequences

- Large UPDATEs are accepted from peers that negotiate Extended Messages
- Non-Extended-Message peers continue with the 4096-byte limit
- Buffer allocation grows only when capability is negotiated
