# ADR-0002: Inherent Methods, Not Traits, for Codec API

**Status:** Accepted
**Date:** 2026-02-27

## Context

The wire crate needs encode/decode functions for each message type. We
considered three approaches:

1. **Codec trait** (`trait Encode`/`trait Decode`) implemented per type
2. **Inherent methods** (`impl OpenMessage { fn decode(...) }`)
3. **Free functions** (`fn decode_open(buf) -> OpenMessage`)

## Decision

Use inherent methods on each message type plus two free functions at the
module level for top-level dispatch:

```rust
// Top-level entry points
pub fn decode_message(buf: &mut Bytes) -> Result<Message, DecodeError>;
pub fn encode_message(msg: &Message) -> Result<BytesMut, EncodeError>;

// Per-type methods
impl OpenMessage {
    pub fn decode(buf: &mut impl Buf) -> Result<Self, DecodeError>;
    pub fn encode(&self, buf: &mut impl BufMut) -> Result<(), EncodeError>;
}
```

Buffer parameters use `impl Buf` / `impl BufMut` from the `bytes` crate
for zero-cost integration with tokio codecs.

## Consequences

- **Positive:** No trait indirection — there is exactly one
  implementation per type, so a trait adds complexity without benefit.
- **Positive:** Matches prior art (bgp-rs, routecore, zettabgp all use
  inherent methods or free functions).
- **Positive:** The transport layer gets a clean integration point via
  `decode_message`/`encode_message` inside a `tokio_util::codec::Decoder`.
- **Negative:** No generic dispatch (`msg.encode()` where `msg: impl Encode`).
  This is fine — the `Message` enum already provides dispatch via match.
