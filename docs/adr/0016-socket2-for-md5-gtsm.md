# ADR-0016: socket2 for TCP MD5 and GTSM socket options

**Status:** Accepted
**Date:** 2026-02-27
**Update (2026-08):** the decision below covered only the active-open
(outbound) socket; the inbound half was unenforced until LAN-902. The passive
BGP listener now installs host-scoped MD5 keys for static neighbors
(`TCP_MD5SIG`) and prefix-scoped keys for dynamic-neighbor ranges
(`TCP_MD5SIG_EXT` + `TCP_MD5SIG_FLAG_PREFIX`, Linux ≥ 4.13) before
`listen()` — the kernel rejects unsigned handshakes from covered peers and
copies the matched key onto accepted children. GTSM is applied per peer on
each accepted socket at accept time (`IP_MINTTL` / `IPV6_MINHOPCOUNT`),
resolved exact-static-first then longest dynamic-range match, because the
shared listener socket cannot carry per-peer TTL policy. Since LAN-907 the
listener is dual-family (`0.0.0.0` + `[::]`, ADR-0019): each MD5 key, TCP-AO
MKT, and GTSM verification is applied on the socket matching the peer's
address family, so IPv6 peers get the same inbound enforcement as IPv4.

## Context

BGP sessions in production typically require TCP MD5 authentication (RFC 2385)
and/or GTSM TTL security (RFC 5082). Both require `setsockopt` calls that must
happen *before* the TCP connection is established:

- `TCP_MD5SIG` (option 14) — associates an MD5 password with a peer address.
- `IP_MINTTL` (option 21) — rejects packets with TTL below 255 (strict RFC 5082 §3.2).

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
