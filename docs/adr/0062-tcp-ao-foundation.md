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

**Negative at foundation time:**

- The first slice left TCP-AO unsupported at runtime until later slices wired
  config and session/listener integration.
- The listener path had to be refactored from direct Tokio binding to a
  `socket2`-created listener so keys could be installed before passive opens.
- Dynamic-neighbor TCP-AO remained out of scope until a prefix/wildcard MKT
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

## Implementation Status

The foundation decision above describes the first ADR-0062 slice. Subsequent
slices have now shipped static-neighbor and startup-only dynamic-range support:

- `[[neighbors]].tcp_ao` is parsed and validated, mutually exclusive with TCP
  MD5, and redacted in config diffs.
- Outbound active-open sockets install the configured TCP-AO keyring before
  `connect()` and fail that connect attempt if any key cannot be installed or
  the resulting kernel inventory cannot be reconciled.
- The passive BGP listener is created through `socket2`, installs configured
  static-neighbor and direct dynamic-prefix TCP-AO keyrings before `listen()`,
  and fails closed if any key cannot be installed.
- SIGHUP additions, removals, edits, or reordering of `tcp_ao` keyrings are
  restart-required and pinned to the live startup snapshot along with
  validation-affecting startup dependencies.
- Runtime deletion of a configured TCP-AO neighbor is rejected until listener
  MKT deletion / live rotation support exists.
- Protected active-open and accepted passive sockets are inspected with
  `getsockopt(TCP_AO_INFO)` plus a bounded `TCP_AO_GET_KEYS` dump after
  connection setup. Raw GET_KEYS records are non-formatting, non-cloning
  temporaries that are zeroized on drop; only peer/prefix, IDs, algorithm,
  selection metadata, optional VRF L3-master ifindex, and counters leave the
  transport boundary. The Linux AO ifindex selector is a VRF identity rather
  than an IPv6 link-local scope; current rustbgpd AO MKTs are VRF-unbound and
  may match any L3 master because `TCP_AO_KEYF_IFINDEX` is clear. Active-open
  and accepted static or dynamic-prefix sockets fail closed unless the complete
  configured keyring, including transient key-byte equality, matches the
  kernel inventory. Dropped-ICMP counters degrade health but do not by
  themselves reject an accepted authenticated socket.
- Protected M43 interop against BIRD 3.2.1 runs in the GitHub-hosted
  `kernel-dataplane` workflow on the current TCP-AO-capable runner. The
  workflow keeps a `CONFIG_TCP_AO` probe so future runner kernels without the
  feature skip M43 with a warning instead of failing unrelated dataplane gates.
- Direct `[[dynamic_neighbors]].tcp_ao` installs a prefix keyring before listen,
  fails closed when accepted socket inspection is missing or inconsistent, and
  pins protected edits until restart. Static-exact ownership precedes dynamic
  longest-prefix-match; Linux's inherited inventory is reconciled as the union
  of every covering protected owner. Such owners may overlap only when their
  SendID sets and RecvID sets are each pairwise disjoint. TCP-AO/plaintext and
  TCP-AO/MD5 overlaps remain rejected. The aggregate listener inventory is
  capped at 4,096 MKTs per address family so the bounded inspection path can
  always verify it completely. Runtime range CRUD cannot mutate or overlap a
  protected range.

Ordered startup keyrings are now supported. A singleton retains the legacy
table shape; multi-key rings are ordered arrays. The preferred key, or the
first declared non-deprecated key, is selected for startup transmission, while
every MKT is installed and reconciled. At most one key may be preferred, each
direction's KeyIDs must be unique within the ring, and at least one key must be
non-deprecated.

Still deferred: live key rotation / deletion on an already-listening socket
(LAN-16 / #159) and peer-group inheritance. API/CLI neighbor state exposes
redacted live inspection results (KeyIDs, validity flags, per-key inventory,
and counters) for
static and direct dynamic-prefix protected sessions; runtime protected-range
CRUD remains restart-gated.
