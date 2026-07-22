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
- SIGHUP can install an immutable add-only successor generation when protected
  owners and existing key material/order are unchanged and every appended MKT
  is non-preferred. Listener and managed session inventories are globally
  preflighted, completely verified, and fenced by generation.
- A later immutable generation can select an already-installed preferred
  successor while keeping the exact owner union, key cores, and order. It sets
  only local RNext, captures the successor's per-key `pkt_good` immediately
  beforehand, and observes the affected session cohort once for matching
  Current/RNext, a strict generation-relative counter increase, and clean
  authentication counters. Only then does it commit predecessor deprecation
  metadata. `awaiting_peer` retains desired N over applied N-1; a later SIGHUP
  must present the identical full candidate and retries N without actor polling.
- A still-later immutable SIGHUP generation can delete only deprecated MKTs
  that are neither Current nor RNext on the listener, queued accepted children,
  or any protected primary/pending session. Owner identity, survivor order,
  key definitions, and the selected MKT remain exact. Listener deletion runs
  first; queued children that inherited the complete adjacent old owner union
  are reconciled before handoff; managed sessions apply concurrently. Any
  changed-session success/ambiguous acknowledgement combined with a cohort
  failure discards the whole changed cohort, and incomplete reset aborts every
  affected task. Failed generations retry only the identical retained inventory
  and only while the listener remains exact (before mutation, after exact-prior
  restoration, or already at desired). After failed restoration, exact-current
  reinspection must succeed before another mutation; otherwise retry is rejected
  and a daemon restart is required while the inventory remains partial or
  unprovable.
- Accepted sockets preserve their complete covering-owner union for both
  selection and inspection; static exact ownership wins, otherwise dynamic
  longest-prefix match selects the owner. The selection generation never
  deletes an MKT or sets Linux Current.
- Runtime deletion of a configured TCP-AO neighbor/owner remains rejected.
  Live MKT deletion cannot remove or move its protected owner.
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
- Linux does not copy keys newly added to a listener into already-established
  children in its accept queue. Such a child is reconciled only when it exactly
  matches the retained immediately previous generation; after adding the
  successor suffix, the exact current inventory and unchanged Current/RNext
  selection are required. Partial, arbitrary-subset, and older inventories are
  rejected. A hosted real-kernel receipt proves this path for a dynamic
  `127.0.0.0/24` owner, retaining its logical owner metadata on the child.
- TCP-AO keys and TCP-MD5 passwords owned by the internal API, peer manager,
  and transport runtime use an immutable redacting wrapper whose independent
  clones zeroize on drop. The short-lived Linux `tcp_md5sig` UAPI record also
  scrubs its key buffer and length after every socket-option attempt. This
  deliberately excludes parser/config/protobuf strings, compiler-created
  copies, and kernel-owned keys.
- Protected M43 interop against BIRD 3.3.1 runs in the GitHub-hosted
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

Ordered keyrings are now supported. A singleton retains the legacy
table shape; multi-key rings are ordered arrays. The preferred key, or the
first declared non-deprecated key, is selected for startup transmission, while
every MKT is installed and reconciled. At most one key may be preferred, each
direction's KeyIDs must be unique within the ring, and at least one key must be
non-deprecated.

Still deferred: key edits/reordering, protected-owner CRUD, and peer-group
inheritance. API/CLI neighbor state exposes redacted live
inspection results (KeyIDs, validity flags, per-key inventory, and counters)
and secret-free desired/applied generation, phase, and failure details for
static and direct dynamic-prefix protected sessions.

The SIGHUP coordinator now consumes the exact deletion foundation. It binds
Linux `TCP_AO_DEL_KEY` to opaque exact-current and exact-survivor receipts,
refuses Current/RNext targets before the syscall, never requests a forced
replacement, uses the exact kernel-returned accepted-child selector, and
verifies the exact post-delete inventory. The Linux 6.17 hosted M43 foundation
receipt proves that an established child preserves and accepts its inherited
`/24` selector for deletion; callers must not replace it with `/32`. The receipt
also fixes the accept-race fact: a child queued before listener deletion retains
the prior inventory, while a later child inherits only the survivors. M43 also
drives the full SIGHUP add/select/deprecate/delete coordinator against BIRD
3.3.1. It requires the exact sole-survivor inventory, unchanged Established
token and flap count, the route present at every sample from a 100 ms polling
oracle, and an increased authenticated-packet count on the surviving MKT before
running the existing mismatched-key fail-closed finale. A separate M43 mode
tests process-crash recovery rather than uninterrupted rotation: after the
add-only generation, during selection/deprecation `awaiting_peer`, and after
delete, it SIGKILLs the daemon and requires BIRD to observe the disconnect. A
new daemon PID starts from the last copied config as fresh generation `1/1` /
`idle` and must recover the exact declared inventory, mandatory TCP-AO with no
authentication fallback, the route and Established session, and the expected
Current/RNext pair. For the selection phase, recovery occurs before BIRD moves:
the exact three-key session is authenticated but correctly `degraded` at
Current `2` / RNext `13` because deprecated key `2` is still in use. The same
fresh generation must become `healthy` at Current `3` / RNext `13` after BIRD
selects the successor. This is process-restart proof inside a surviving
container; it is not a host-reboot persistence claim.

## Linux UAPI secrecy and normalization boundary

The Linux v6.17 [`tcp_ao_add`
UAPI](https://github.com/torvalds/linux/blob/v6.17/include/uapi/linux/tcp.h#L378-L402)
defines `keyflags` separately from its selection flags. rustbgpd supplies zero:
`TCP_AO_KEYF_IFINDEX` and `TCP_AO_KEYF_EXCLUDE_OPT` are both clear, so an MKT is
not VRF-bound and [TCP options remain covered by
authentication](https://github.com/torvalds/linux/blob/v6.17/net/ipv4/tcp_ao.c#L600-L602).
Linux
[`TCP_AO_GET_KEYS`](https://github.com/torvalds/linux/blob/v6.17/net/ipv4/tcp_ao.c#L2259-L2286)
zeroes each output record and reconstructs an IPv6 family, port, and address,
but not `sin6_scope_id`. IPv6 scope therefore remains socket/config authority,
not an AO MKT selector.

The raw add and GET_KEYS records contain key bytes and algorithm/key-length
metadata, deliberately implement neither `Debug` nor `Clone`, and scrub those
fields on drop. Reconciliation copies key bytes only into a
`Zeroizing<Vec<u8>>` normalized core. The sole raw-address decoding boundary
reads the `sockaddr_in` or `sockaddr_in6` prefix selected by the kernel-supplied
family; no raw secret-bearing record crosses into CLI/API state. These rules
track the [GET_KEYS record](https://github.com/torvalds/linux/blob/v6.17/include/uapi/linux/tcp.h#L438-L465)
and Linux's [full-header hashing when options are
included](https://github.com/torvalds/linux/blob/v6.17/net/ipv4/tcp_ao.c#L526-L551).
