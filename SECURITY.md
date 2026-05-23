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
- **No `unsafe` code.** Every crate enforces `#![deny(unsafe_code)]`.
- **Structured errors, not strings.** Every failure produces a
  machine-parseable event for forensic analysis.

### Authentication (v1)

- **TCP MD5 (RFC 2385):** Supported. Linux only.
- **GTSM (RFC 5082):** Supported. Configurable per peer.
- **TCP-AO (RFC 5925):** Supported for static neighbors on Linux (ADR-0062, startup key install). Dynamic-neighbor, runtime key rotation, and multi-key rollover remain roadmap items.
- **gRPC:** Unix domain socket by default (local-only). TCP listeners
  are opt-in via config. Per-listener bearer-token authentication is
  available via `token_file`. Native mTLS terminates in-process on TCP
  listeners via tonic + rustls/ring — configure `tls_cert_file`,
  `tls_key_file`, and `tls_client_ca_file` together on
  `[global.telemetry.grpc_tcp]` (partial config is rejected at config
  load). An mTLS proxy front-end (see `examples/envoy-mtls/`) remains a
  valid alternative for multi-host fan-out. Per-RPC authorization tiers
  (ADR-0064, enforced by default since v0.24.0) classify each method on
  top of the listener split; see [docs/SECURITY.md](docs/SECURITY.md) and
  [docs/grpc-method-inventory.md](docs/grpc-method-inventory.md).

### Rate Limiting

- Max inbound TCP connections per source IP: configurable (default 5/min)
- Max total pending connections: configurable (default 100)
- Connections from unconfigured peers dropped immediately after TCP accept
