# ADR-0062: TCP-AO foundation

**Status:** Accepted
**Date:** 2026-05-16

## Context

rustbgpd supports TCP MD5 (RFC 2385) and GTSM (RFC 5082) through the
`socket2` boundary described in ADR-0016. TCP-AO (RFC 5925) is the modern
replacement for TCP MD5: it uses TCP option kind 29, supports stronger MAC
algorithms, includes connection-specific key derivation, and supports key
rollover through KeyID / RNextKeyID.

Linux exposes TCP-AO through per-socket options:

- `TCP_AO_ADD_KEY` (38) for adding a Master Key Tuple.
- `TCP_AO_DEL_KEY` (39) for deleting a key.
- `TCP_AO_INFO` (40) / `TCP_AO_GET_KEYS` (41) for status and inspection.

The running privileged test host has `CONFIG_TCP_AO=y`, and a minimal
`setsockopt(TCP_AO_ADD_KEY)` probe succeeds when shaped like the Linux
`tools/testing/selftests/net/tcp_ao` capability check.

Full rustbgpd TCP-AO support is not just an outbound connect change. TCP-AO
keys must exist before active or passive OPEN. The outbound path already
creates a `socket2::Socket` before connect, but the inbound listener currently
uses `tokio::net::TcpListener::bind` directly and has no pre-listen key
installation hook.

## Decision

Land TCP-AO in staged slices.

The foundation slice adds only:

1. Internal Linux UAPI constants and `repr(C, align(8))` structs for
   `tcp_ao_add` and `tcp_ao_info_opt`.
2. An internal `set_tcp_ao_key()` helper in `crates/transport/src/socket_opts.rs`.
3. A kernel capability probe that distinguishes unsupported kernels from
   probe failures.
4. Binding and encoding tests for layout, constants, peer-address encoding,
   algorithm names, key length, and prefix validation.

This slice intentionally does **not** add operator TOML fields or claim runtime
TCP-AO support. Accepting TCP-AO config before the listener and outbound paths
apply it would be a silent security footgun.

## Consequences

**Positive:**

- Establishes the unsafe Linux socket boundary before touching session
  orchestration.
- Keeps operator behavior unchanged until TCP-AO can be applied correctly on
  active and passive opens.
- Gives follow-on slices tested UAPI building blocks and capability probing.

**Negative:**

- TCP-AO remains unsupported at runtime until later slices wire config and
  session/listener integration.
- The listener path must be refactored from direct Tokio binding to a
  `socket2`-created listener so keys can be installed before passive opens.
- Dynamic-neighbor TCP-AO remains out of scope until a prefix/wildcard MKT
  design exists.

## Follow-up Slices

1. Add static-neighbor TCP-AO config schema, mutually exclusive with
   `md5_password`, with key IDs, secret, preferred/deprecated flags, and
   algorithm validation.
2. Refactor the inbound listener to support pre-listen socket option
   installation.
3. Apply AO keys on outbound active-open sockets and listener sockets.
4. Add a protected-runner interop smoke against a TCP-AO peer implementation
   such as BIRD 3.x on Linux.
