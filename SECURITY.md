# Security Policy

This is the vulnerability-reporting policy. For operational security
guidance — deployment tiers, mTLS setup, gRPC authorization, and audit
logging — see [docs/SECURITY.md](docs/SECURITY.md).

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.x     | Yes (current development) |

## Reporting a Vulnerability

Report security vulnerabilities via
[GitHub Security Advisories](https://github.com/lance0/rustbgpd/security/advisories/new).

**Do not open a public issue for security vulnerabilities.**

### What Qualifies

- Remote crash (panic on malformed BGP input)
- Session hijacking or injection
- Denial of service via resource exhaustion
- Memory safety violations
- Authentication bypass (TCP MD5, GTSM)

### Response Timeline

- **Acknowledgment:** Within 48 hours
- **Critical vulnerabilities** (remote crash, session hijack): Patched
  and released within 72 hours of confirmation
- **Other vulnerabilities:** Patched in the next milestone release

## Security Posture

### Attack Surface

The wire decoder is the primary attack surface. It processes untrusted
input from the network. It runs under continuous fuzzing in CI.

### Design Principles

- **No panics on malformed input.** Every input from the network is
  untrusted. A panic on malformed BGP data is a denial-of-service
  vulnerability.
- **No unbounded allocations.** All channels are bounded. Per-peer
  prefix limits enforced at insertion. UPDATE attribute sizes enforced
  at decode time.
- **No `unsafe` code in shipped paths, with two scoped exceptions.** Every
  workspace crate root carries `#![deny(unsafe_code)]`, so `unsafe` cannot enter
  a crate without a visible, reviewed opt-out. There are two:
  - `crates/transport`'s `socket_opts` module carries a documented
    `#[allow(unsafe_code)]` for socket-option FFI (`TCP_MD5SIG`, `IP_MINTTL`,
    TCP-AO) that has no safe Rust API. This is the only `unsafe` in any library
    crate.
  - The daemon binary's deny is `cfg_attr`-gated off when the `jemalloc` (the
    default) or `dhat-heap` feature is on, because registering a
    `#[global_allocator]` is itself an `unsafe` construct. Building with
    `--no-default-features` re-arms the deny; the daemon writes no `unsafe`
    blocks of its own under either configuration.

  Test and benchmark targets are separate compilation units and are not covered
  by a crate root's deny. Several carry justified `unsafe`: allocation-tracking
  `GlobalAlloc` wrappers used by the memory-profile receipts (`crates/mrt`
  benches, `crates/rib` tests, the standalone `bench/scale` harnesses) and
  `libc` socket/netns helpers in the privileged `crates/evpn-linux` tests. None
  of that code ships in the daemon or in any published library crate.
- **Structured errors, not strings.** Every failure produces a
  machine-parseable event for forensic analysis.

### Authentication (v1)

- **TCP MD5 (RFC 2385):** Supported. Linux only.
- **GTSM (RFC 5082):** Supported. Configurable per peer.
- **TCP-AO (RFC 5925):** Supported for static neighbors and direct
  dynamic-prefix listener keys on Linux (ADR-0062), including ordered startup
  keyrings, fail-closed accepted-socket owned-union validation, and live
  API/CLI health. SIGHUP can append non-preferred successor keys to unchanged
  owners, then select the successor (observation-gated deprecation of the
  predecessor) and later delete deprecated/unselected keys across further
  SIGHUP generations. Key edits/reordering, selected or non-deprecated-key
  deletion, and protected-owner changes remain restart-required. Static-exact
  selection precedes dynamic longest-prefix-match; overlapping protected
  owners require directionally disjoint KeyIDs, AO/plaintext or AO/MD5
  overlaps are rejected, and listener inventories are capped at 4,096 MKTs
  per address family.
- **gRPC:** Unix domain socket by default (local-only). TCP listeners
  are opt-in via config. Per-listener bearer-token authentication is
  available via `token_file`. Native mTLS terminates in-process on TCP
  listeners via tonic + rustls/ring — configure `tls_cert_file`,
  `tls_key_file`, and `tls_client_ca_file` together on
  `[global.telemetry.grpc_tcp]` (partial config is rejected at config
  load). SIGHUP re-reads credential bytes from unchanged startup-captured
  paths and publishes one atomic generation across all listeners before later
  config reconciliation. New RPCs, including on existing HTTP/2 connections,
  use the new bearer token; new TLS accepts use the new mTLS material, while
  existing streams and TLS connections survive. Listener, path, auth-mode,
  principal, role, and access changes remain restart-required. An mTLS proxy
  front-end (see `examples/envoy-mtls/`) remains a valid alternative for
  multi-host fan-out. Per-RPC authorization tiers
  (ADR-0064, enforced by default since v0.24.0) classify each method on
  top of the listener split; see [docs/SECURITY.md](docs/SECURITY.md) and
  [docs/grpc-method-inventory.md](docs/grpc-method-inventory.md).

### Rate Limiting

- Max inbound TCP connections per source IP: configurable (default 5/min)
- Max total pending connections: configurable (default 100)
- Connections from unconfigured peers dropped immediately after TCP accept
