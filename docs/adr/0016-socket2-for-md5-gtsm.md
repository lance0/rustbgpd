# ADR-0016: socket2 for TCP MD5 and GTSM socket options

**Status:** Accepted
**Date:** 2026-02-27

## Context

BGP sessions in production typically require TCP MD5 authentication (RFC 2385)
and/or GTSM TTL security (RFC 5082). Both require `setsockopt` calls that must
happen *before* the TCP connection is established:

- `TCP_MD5SIG` (option 14) — associates an MD5 password with a peer address.
- `IP_MINTTL` (option 21) — rejects packets with TTL below 254.

Tokio's `TcpStream::connect()` creates and connects in one step, providing no
window to apply socket options.

## Decision

Use `socket2::Socket` to create the TCP socket manually:

1. Create socket via `socket2::Socket::new()`.
2. Apply MD5 and/or GTSM options via raw `setsockopt` calls.
3. Set non-blocking mode.
4. Call `socket.connect()` (returns `EINPROGRESS` for non-blocking).
5. Convert to `std::net::TcpStream`, then `tokio::net::TcpStream`.
6. Await `stream.writable()` for connection completion.

The `unsafe` blocks live in `crates/transport/src/socket_opts.rs` with
`#[allow(unsafe_code)]` on the module. The rest of the transport crate
retains `#![deny(unsafe_code)]`.

Non-Linux platforms get stub implementations that return `io::ErrorKind::Unsupported`.

## Consequences

**Positive:**
- MD5 and GTSM work correctly — options applied before TCP handshake.
- Unsafe code is isolated to one module with clear documentation.
- No runtime overhead on platforms/configs that don't use these features.

**Negative:**
- Two new dependencies (`socket2`, `libc`).
- The only `unsafe` code in the project — requires extra review scrutiny.
- Linux-only for MD5/GTSM (documented limitation).
