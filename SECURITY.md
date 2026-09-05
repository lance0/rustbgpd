# Security Policy

This is the vulnerability-reporting policy. For operational security
guidance — deployment tiers, mTLS setup, gRPC authorization, and audit
logging — see [docs/reference/security.md](docs/reference/security.md).

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.x     | Yes (current development) |

Daemon security support follows the Linux-only
[platform support contract](SUPPORT.md#platform-support).

## Reporting a Vulnerability

Report security vulnerabilities via
[GitHub private vulnerability reporting](https://github.com/lance0/rustbgpd/security/advisories/new),
which is enabled on this repository.

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

### CVE Assignment

Qualifying vulnerabilities are published as GitHub Security Advisories
once a fix is released, and a CVE ID is requested for each through
GitHub's GHSA-to-CVE assignment flow.

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
- **Commit-confirm state is authenticated local authority.** Production writes
  v3 in durability order: secret-bearing normalized configuration at
  `<runtime_state_dir>/commit-confirm-v3-prior.toml`, confidential provenance
  and file-identity metadata at `commit-confirm-v3-metadata.json`, then the
  confidential config-adjacent `<config>.commit-confirm-locator.json`. Metadata
  and the locator contain paths and digests, not raw TOML; the locator is the sole boot
  authority. All are bounded daemon-owned regular `0600` files, and a writer or
  present pending object requires daemon-owned real parents that are not group-
  or world-writable. Reads are descriptor-relative, no-follow, same-FD
  operations; unsafe, changed, oversized, or mismatched state fails closed
  before candidate contents are opened or candidate/backup mutation. Durable
  locator unlink plus parent `fsync` is terminal; only later verified exact
  metadata/raw cleanup and pending-directory `fsync` can fail warning-only.
  Locator absence carries no v3 authority. A retired v2 locator or locator-free
  v1/v2 journal makes v0.65.0 and every later release refuse boot before
  candidate mutation, and remains untouched for recovery with rustbgpd v0.64.0.
- **No `unsafe` code in shipped paths outside three scoped modules.** Every
  workspace crate root carries `#![deny(unsafe_code)]`, so `unsafe` cannot enter
  a crate without a visible, reviewed opt-out. Three modules hold one:
  - `crates/transport`'s `socket_opts` module, opted out by a module-level
    `#[allow(unsafe_code)]` in the crate root and a per-function
    `#[allow(unsafe_code, reason = ...)]` on each site inside it. Every site is
    Linux socket-option ABI with no safe Rust wrapper: `TCP_MD5SIG` /
    `TCP_MD5SIG_EXT`, TCP-AO key installation, deletion, inspection and RNext
    selection, GTSM (`IP_MINTTL` / `IPV6_MINHOPCOUNT`), and the `sockaddr_in` /
    `sockaddr_in6` encoding those options take.
  - `crates/api`'s `runtime_config_settlement` module: the
    ambiguous-configuration watchdog's terminal boundary is
    `#[cfg(not(test))] fn terminate_process()`, whose entire body is
    `unsafe { libc::_exit(70) }`. It is exit-only by construction, and that is
    enforced rather than asserted — a unit test parses the production source and
    requires the body to be exactly that call and to contain no allocation,
    lock, drop, panic, logging, or metric term, so nothing runs between the
    fence decision and process exit.
  - The daemon binary's `bfd_runtime` module: one raw `setsockopt` enabling
    `IP_RECVTTL` / `IPV6_RECVHOPLIMIT`, which `socket2` does not expose. BFD
    needs the received TTL delivered as ancillary data to enforce the RFC 5881
    exact-255 receive check.

  The daemon binary carries the same unconditional crate-root deny with its
  default `jemalloc`, opt-in `dhat-heap`, and no-default-feature configurations.
  Registering either dependency-provided allocator introduces no `unsafe` block
  or `unsafe impl` in this crate. The three shipped boundaries above remain
  visible, reviewed opt-outs with recorded reasons.

  Test and benchmark targets are separate compilation units and are not covered
  by a crate root's deny. Several carry justified `unsafe`: allocation-tracking
  `GlobalAlloc` wrappers used by the memory-profile receipts (crate benches and
  tests, plus the standalone `bench/scale` harnesses) and `libc` socket/netns
  helpers in the privileged `crates/evpn-linux` tests. None of that code ships
  in the daemon or in any published library crate.
- **Structured errors, not strings.** Every failure produces a
  machine-parseable event for forensic analysis.

### Memory Safety

rustbgpd is written in Rust, consistent with product-security guidance
published by CISA and partner agencies recommending memory-safe languages
for software that processes untrusted network input. The enforcement
mechanism is the crate-root `#![deny(unsafe_code)]` invariant described
under Design Principles above: no `unsafe` in shipped paths beyond the
three documented, scoped modules.

One concrete bound this pins: `AS_PATH` matching is length-bounded under
RFC 8654 Extended Messages. The policy engine matches the rendered path
string with no fixed-capacity per-ASN buffer anywhere in the match path;
`crates/policy/tests/as_path_extended_message_bound.rs` decodes a
maximum-size (65,533-byte) UPDATE and proves regex and length matching
see the full ~16,000-ASN path.

### Fuzzing

Six fuzz crates (`crates/wire`, `crates/policy`, `crates/mrt`,
`crates/evpn`, `crates/bfd`, `crates/rpki`) carry fuzz targets covering
the message decoders, the policy frontend, structure-aware policy-chain
compilation and explain-walk agreement, MRT snapshot and warm-bundle
readers, EVPN parsing, the BFD control-packet decoder, and the RTR PDU
decoder. A nightly CI campaign (`.github/workflows/fuzz.yml`) runs every
target in each crate against tracked seed corpora and fails loudly if
target enumeration returns nothing. In both nightly and hosted campaigns,
the complete-message wire target accepts 65,535-byte RFC 8654 messages and
the body-only UPDATE and ROUTE-REFRESH targets accept the corresponding
65,516-byte bodies. Pre-negotiation OPEN bodies remain capped at the legacy
4,077-byte body boundary. A ClusterFuzzLite workflow builds all targets with
AddressSanitizer for on-demand campaigns. The target
inventory is fail-closed: `scripts/check_fuzz_target_inventory.py` runs
in CI and fails when the inventory drifts from the reviewed list.
Every wire target has a tracked seed. The nightly workflow may reuse a bounded
`main`-lineage corpus, but it restores into runner-temporary staging and
validates the exact reviewed target-directory set, regular-file shape,
per-target length bounds, SHA-256 manifest, 20,000-file ceiling, and 16 MiB
ceiling before copying anything into the live corpus. Cache misses and
cache-service outages use only the tracked seeds; matched content that fails
validation stops the campaign.
The cache contains public test inputs only and is not a place for credentials
or other private data.

### Notes for Integrators

Integrators documenting rustbgpd's upstream open-source handling can point at:

- This coordinated disclosure policy, including the response timelines
  above.
- Private vulnerability intake via GitHub private vulnerability
  reporting, enabled on the repository.
- CVE assignment for qualifying vulnerabilities via the GHSA flow.
- Exact dependency inventory in the committed `Cargo.lock` for every tagged
  source tree.
- MIT or Apache-2.0 licensing; software and release artifacts are provided
  as-is under those licenses.

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
  top of the listener split; see [docs/reference/security.md](docs/reference/security.md) and
  [docs/reference/grpc-method-inventory.md](docs/reference/grpc-method-inventory.md).

### Inbound Connection Handling

- Inbound connections from source addresses matching no configured static
  neighbor and no `[[dynamic_neighbors]]` range are dropped immediately
  after TCP accept.
- Dynamic-neighbor admission is capped by `dynamic_neighbor_limit`
  (restart-pinned); connections beyond the cap are dropped and counted.
- An opt-in per-source accept-rate limiter (`[inbound_admission]`,
  ADR-0120, default off) token-buckets sources that match a
  `[[dynamic_neighbors]]` range, keyed by aggregated source address
  (per-host for IPv4, per-/64 for IPv6 by default; both configurable).
  Over-rate connections are dropped immediately after accept and counted
  in `bgp_inbound_connections_dropped_total{reason="rate_limited"}`.
  Tracking state is a fixed-capacity LRU table, so limiter memory is
  bounded regardless of offered load. Statically configured neighbor
  addresses are exempt so a flapping legitimate peer cannot lock itself
  out of re-establishment.
- The message-processing path between peer sessions and the RIB uses
  bounded channels, so a fast or abusive peer parks on backpressure
  instead of growing daemon memory (see Design Invariant #3 in
  [docs/explanation/architecture.md](docs/explanation/architecture.md) for the channel policy).
