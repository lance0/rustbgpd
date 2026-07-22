# ADR-0117: Authenticated single-hop BFD remains demand and interoperability gated

**Status:** Accepted (implementation NO-GO; evidence-gated reconsideration)
**Date:** 2026-07-22

## Context

ADR-0067 ships single-hop asynchronous BFD for static BGP neighbors.  The
in-process actor enforces UDP port and source-port rules, transmits and accepts
only TTL / Hop-Limit 255, reports session state through metrics, gRPC, CLI, and
events, and couples BFD loss to BGP in strict and non-strict modes.  It
deliberately defers the optional RFC 5880 Authentication Section.

Authentication solves a real but narrow route-server problem.  An IXP route
server commonly shares a Layer-2 peering LAN with many members.  TTL / Hop-
Limit 255 prevents an off-link sender from forging a single-hop BFD packet, but
it does not establish which on-link member sent the packet.  A member able to
spoof another member's source address could try to inject BFD `Down`,
`AdminDown`, or apparently live traffic.  RFC 5880 notes that a forged BFD
state can falsely declare a path up or down and cause denial of service; its
two mitigations are the TTL / Hop-Count check and the Authentication Section.

The incremental benefit is weaker for a route reflector on a private,
point-to-point, or otherwise trusted underlay.  Authentication also cannot
defeat an attacker who controls the link and can selectively forward or drop
BFD traffic.  It is therefore not a blanket security requirement for every
BFD session, and general standards parity is not sufficient demand.

### Existing implementation boundary

The current implementation is technically suitable for a bounded extension:

- `crates/bfd/src/packet.rs` owns the mandatory control-packet codec.  It
  validates the Authentication Present bit structurally but does not retain or
  verify the trailing section.
- `crates/bfd/src/session.rs` is a pure sans-IO state machine.  It currently
  discards every packet with the Authentication Present bit set before the
  packet can affect session state.
- `src/bfd_runtime.rs` is the sole owner of sockets, discriminators, real
  timers, per-peer status, and the bounded receive loop.  Authentication does
  not require a second daemon or a second owner.
- `[[bfd_profiles]]` and per-neighbor / peer-group BFD attachments are already
  restart-required and pinned across reload.  An initial authenticated slice
  need not invent live actor reconfiguration.
- BFD config and API surfaces are explicitly outside the v1 stable contract,
  so additive authenticated-session status would not silently expand the v1
  promise.  Existing effective-config, diagnostic, audit, and API redaction
  machinery already protects other transport secrets, but BFD keys would
  still need explicit coverage and proof.

The non-trivial addition is replay state.  `TimerKind` currently has only
transmit and detection timers.  RFC 5880 requires the learned receive sequence
to become unknown after at least twice the Detection Time without a received
packet, so a restarted peer can resynchronize from a new random sequence.  A
correct implementation needs an actor-owned resynchronization deadline (or an
equivalent deterministic session event); clearing the sequence at the first
detection expiry is too early, while never clearing it wedges restart recovery.

### Exact RFC 5880 contract

If authentication is implemented, RFC 5880 requires support for both Keyed
SHA-1 and Meticulous Keyed SHA-1.  Simple Password and the MD5 variants are not
required and add no justified compatibility value here.

Both SHA-1 variants use a 28-byte Authentication Section after the 24-byte
mandatory control packet, for a total BFD Control packet length of 52 bytes:

| Field | Required value |
|-------|----------------|
| Authentication Type | 4 for Keyed SHA-1; 5 for Meticulous Keyed SHA-1 |
| Authentication Length | 28 |
| Authentication Key ID | ID of the selected configured key |
| Reserved | Zero on transmit; ignored on receipt |
| Sequence Number | Current 32-bit transmit authentication sequence |
| Authentication Hash | 20-byte SHA-1 result over the complete packet |

The wire construction is specifically the RFC's secret-suffix construction,
not HMAC-SHA1: the secret, padded with trailing zeroes to 20 bytes, occupies the
Authentication Hash field while SHA-1 is calculated over the complete packet;
the result then replaces that field.  RFC 5880 permits a shared secret of up to
20 bytes; an activated rustbgpd config must reject an empty secret.  The
management surface must accept ASCII and may add an explicit hexadecimal form
for arbitrary binary keys without changing the wire algorithm.

Transmit sequence initialization and advancement are distinct:

- Every new session initializes its 32-bit transmit authentication sequence
  from an unpredictable value.
- Keyed SHA-1 may reuse a sequence across ordinary periodic packets, but it
  should advance when session state or transmitted packet contents change.
- Meticulous Keyed SHA-1 advances for every transmitted control packet,
  including immediate Final or AdminDown packets as well as timer sends.

Receive comparisons operate in the unsigned 32-bit circular number space.  If
the receive sequence is known, Keyed SHA-1 accepts only the inclusive range
from the last accepted sequence through `last + (3 * Detect Mult)`.  The
meticulous variant accepts only `last + 1` through the same upper bound.  A
plain integer `<` or `>` comparison is wrong at wraparound; omitting the upper
bound lets a single accepted far-ahead packet advance receive state beyond
legitimate traffic that follows.

When the receive sequence is unknown, the first packet may establish it only
after the Key ID, mode, length, and digest all validate.  Verified RFC 5880
Erratum 7083 corrects Section 6.7.4's processing order: digest failure discards
the packet before `bfd.AuthSeqKnown` or `bfd.RcvAuthSeq` changes.  Validation
must not mutate the stored sequence, refresh the detection deadline, or affect
the BFD state until the whole packet passes.  After no authenticated packet has
been received for at least twice the Detection Time, the receive sequence
becomes unknown so a restarted peer's new random sequence can be learned.

Authentication does not replace the RFC 5881 single-hop envelope.  UDP
destination port 3784, the 49152 through 65535 source-port range, stable source
port per session, and interface/session demultiplexing remain mandatory.  RFC
5881 requires authenticated BFD Control packets to be transmitted with TTL /
Hop-Limit 255, but makes discarding an authenticated packet received with any
other value optional.  rustbgpd deliberately retains its stricter project
policy: every received single-hop BFD Control packet must have TTL / Hop-Limit
255, including when authentication is enabled.

### Current interoperability audit

This audit uses released official documentation and source as of 2026-07-22.
It is source inspection, not an authenticated rustbgpd interop receipt.

| Implementation | Current authenticated-BFD surface | Consequence |
|----------------|-----------------------------------|-------------|
| BIRD 3.3.1 | Documents basic and meticulous keyed SHA-1, multiple Key IDs, and independent signing/acceptance lifetimes.  Its released `proto/bfd/packets.c` fills the hash field with the padded secret, calculates SHA-1 over the packet, and applies the circular `3 * Detect Mult` receive window. | The only standards-shaped interop target among the compared daemons.  A real lab is still required before rustbgpd may claim compatibility. |
| FRR 10.7.0 | Documents key-chain `hmac-sha-1` and an optional meticulous mode.  Released `bfdd/bfd_packet.c` uses OpenSSL `HMAC()` with the key as the HMAC key and a zeroed digest field.  Its receive sequence checks also use linear comparisons and do not enforce the RFC upper window. | Source inspection indicates that RFC secret-suffix SHA-1 packets and FRR's HMAC packets will not authenticate each other.  rustbgpd must not claim FRR auth interop from the matching type numbers alone. |
| GoBGP 4.7.0 | Ships native single-hop BFD, but its official BFD documentation explicitly lists authentication as out of scope. | Authenticated sessions cannot be enabled toward GoBGP. |
| OpenBGPD 9.1 | The released portable source and BGP manuals expose no BFD implementation. | No BFD or authenticated-BFD interop target exists. |

The FRR conclusion is intentionally narrow: it describes the inspected 10.7.0
source.  It does not speculate about operator patches or future releases.  A
future FRR correction must be demonstrated with a packet-level interop receipt,
not inferred from configuration vocabulary.

## Decision

Do **not** implement BFD authentication now.  Record an implementation NO-GO
until both operator demand and a standards-correct interoperability target are
concrete.

The architecture is not the blocker.  The current value proposition is one
open-source peer implementation, BIRD, and no named deployment in this
repository that requires authenticated BFD.  Shipping an unproven security
surface would add secret lifecycle, per-packet cryptography, replay state, and
operator failure modes while leaving FRR, GoBGP, and OpenBGPD peers unable to
use it.

Implementation may be reconsidered only when all of these gates pass:

1. **Named demand.** A named IXP or RR operator requires authenticated BFD and
   identifies the peer implementation and topology.  The motivating boundary
   must be an on-link spoofing risk or an equivalent concrete threat, not a
   parity checklist.
2. **Base receipt stays current.** The unauthenticated M51 BFD re-receipt is
   green on current main via #1093 (`8b8f76e8`).  Authentication work must
   rerun that gate against its base rather than hide a base BFD regression.
3. **Standards-shaped peer.** A disposable BIRD 3.3.1 lab proves Keyed SHA-1
   and Meticulous Keyed SHA-1 in both directions, using captured packets to
   confirm the 52-byte secret-suffix wire construction.
4. **Rollover demand is explicit.** The operator accepts startup-pinned manual
   rollover, or a separate proposal justifies live actor reconfiguration.  A
   request for hitless key rotation must not silently inflate the initial
   slice.
5. **FRR posture is honest.** Either a released FRR version demonstrates RFC
   5880 interop, or the feature remains explicitly unsupported toward FRR.
   Matching `Auth Type` values are not sufficient evidence.
6. **Actor cost is measured.** A real, non-stub BFD actor establishes the
   per-packet cryptographic cost against immediately preceding main.  The
   receipt discloses session count, timer floor, packet rate, invalid-packet
   load, and host shape; an in-code counter or assertion proves the digest path
   ran.  It must show that transmit, detection, and shutdown deadlines do not
   starve under the existing bounded receive-work policy.

### Bounded future scope after the gates

If activated, keep the implementation in four independently reviewable
tranches.  The line caps cover production code and intentionally exclude
tests, fixtures, generated schema, and documentation.

1. **Pure codec and FSM (at most 450 production lines).** Retain and encode the
   exact 52-byte authenticated packet, implement constant-time digest
   comparison, both SHA-1 modes, circular replay windows, unpredictable
   transmit initialization, and twice-Detection-Time resynchronization.  No
   socket or config changes ride in this tranche.
2. **Startup-pinned key model (at most 450 production lines).** Add an optional
   keyring to BFD profiles, local validation, effective-config/schema output,
   restart-required diff/pinning, and complete secret redaction.  Absence keeps
   today's unauthenticated behavior byte-for-byte; enabling auth is explicit.
3. **Actor and operator surface (at most 500 production lines).** Add the
   resynchronization timer, actor-side key resolution, bounded metrics, status,
   CLI/doctor visibility, and rate-limited diagnostics.  BGP coupling continues
   to consume only the resulting BFD level and does not learn key material.
4. **Real interop and docs (at most 300 non-test lines).** Add a BIRD lab for
   both modes, wrong-key isolation, restart recovery, and manual overlapping-
   key rollover; publish the packet and performance receipts.

Explicitly excluded from this decision and any activated first slice:

- multihop BFD, echo mode, or demand mode;
- dynamic-neighbor BFD;
- IPv6 link-local / unnumbered BFD;
- Simple Password, Keyed MD5, or Meticulous Keyed MD5;
- local forwarding-plane, static-route, or non-BGP BFD consumers;
- a nonstandard FRR HMAC compatibility mode;
- live authentication enable/disable or time-scheduled key activation;
- changes to BGP graceful-restart or BFD C-bit semantics.

### Key lifecycle if activated

Keep the initial lifecycle manual and independent of wall-clock time.  Clock-
scheduled signing and acceptance windows create a new NTP/backstep correctness
boundary and are not required to prove the feature.

- One profile selects one explicit mode: Keyed SHA-1 or Meticulous Keyed
  SHA-1.  A mode is never learned or downgraded from received traffic.
- Multiple unique receive Key IDs may be accepted during rollover, but exactly
  one key is selected for transmit.  A deprecated key may remain receive-only;
  it is never selected for new sends.
- A received Key ID selects only an acceptance key for that peer.  It must
  never select the local transmit key or affect another peer's key state.
- Secrets are 1 through 20 bytes.  ASCII is the mandatory management form; an
  explicit hexadecimal form is optional future scope if the named deployment
  needs arbitrary binary keys.
- Keyring edits remain restart-required with the existing BFD actor model.
  Manual rollover therefore uses an overlap phase, an explicit transmit-key
  switch, and a later old-key removal across controlled restarts.  If that
  operational cost is unacceptable, live rollover requires its own design and
  proof rather than an unreviewed exception.
- An authenticated session accepts only its configured mode.  Missing auth,
  an unexpected mode, unknown Key ID, wrong length, digest mismatch, or replay-
  window failure is discarded before state or timers change.  There is no
  opportunistic RFC 5880 Section 6.7.1 transition between authenticated and
  unauthenticated operation.

### Observability and redaction if activated

Operators must be able to distinguish path failure from auth failure without
receiving secret material.  The bounded surface should expose:

- configured authentication mode and whether the current session is protected;
- transmit Key ID and optional last successfully received Key ID;
- bounded counters for `missing`, `unexpected`, `type`, `unknown_key`,
  `length`, `digest`, and `sequence` failures;
- session state and the existing BGP-coupling result.

Key IDs and bounded reasons are operational metadata.  Secrets, padded secret
blocks, packet hashes, and authentication sequence values must never appear in
gRPC, CLI JSON, effective-config output, audit summaries, config diffs, parse-
error snippets, `Debug`, logs, metrics labels, events, or panic text.  Logs may
carry peer, mode, Key ID, and reason only, and must be rate-limited so on-link
bad traffic cannot turn authentication into a log or actor-starvation attack.
Failure counters are per peer; a wrong key for peer A cannot alter peer B's
state, timers, counters, or BGP coupling.

### Load-bearing validation if activated

Every test or gate below must be demonstrated red when its guarded production
logic is removed:

- A BIRD-captured valid packet passes; changing one authenticated byte fails.
  Removing digest verification must make the mutation pass and the test red.
- Equal sequence is accepted for basic Keyed SHA-1 and rejected for meticulous
  mode.  Removing strict meticulous advancement must make its replay test red.
- A sequence beyond `3 * Detect Mult` is rejected.  Removing the upper bound
  must make that test red.
- Acceptable sequences spanning `u32::MAX -> 0` pass.  Replacing circular
  arithmetic with ordinary ordering must make the wrap test red.
- A restarted peer remains rejected before, and can resynchronize after,
  twice the Detection Time.  Removing the resynchronization event must make
  the recovery test red; clearing at the first detection expiry must make the
  early-reset test red.
- A valid sequence paired with a bad digest does not poison receive state.
  Mutating sequence state before digest success must make the following valid
  packet fail and the regression red.
- An authenticated session rejects an otherwise valid unauthenticated packet
  without refreshing detection.  Removing fail-closed mode enforcement must
  make the timeout test red.
- A wrong-key flood for one peer cannot keep that peer alive, starve due
  timers, or touch another peer.  Removing peer isolation or the receive-work
  cap must make the actor test red.
- BIRD basic and meticulous sessions reach Up; changing the key after Up drives
  only the intended BFD/BGP session down, while an initially wrong key keeps a
  strict BGP session withheld.  Restart recovery returns Up.  The lab must fail
  if rustbgpd sends HMAC-SHA1 or skips the replay checks.

Performance receipts use main immediately before the implementation as the
control, a real actor/socket path, and the same compiler/profile.  A bare
`black_box` benchmark or a codec-only throughput number is insufficient: the
gate is actor fairness and BFD deadline behavior at the disclosed fleet shape.

## Alternatives considered

### Keep TTL / Hop-Limit 255 only

This remains the decision for current deployments.  It is mandatory and
cheap, and it blocks off-link spoofing.  It does not authenticate an on-link
member on a shared peering LAN, so concrete IXP demand may justify revisiting
this ADR.

### Implement FRR's HMAC-SHA1 wire behavior

Rejected.  Reusing RFC Authentication Type 4 or 5 with a different digest
construction would create a mode that looks standards-compatible but is not.
Dual digest modes would expand downgrade, configuration, testing, and operator
failure surfaces for one implementation-specific behavior.

### Add Simple Password or MD5 for compatibility

Rejected.  Simple Password exposes the secret on the LAN, and RFC 5880
discourages the MD5 variants.  Authentication implementations are required to
support both SHA-1 variants; adding weaker modes does not unlock a documented
target unavailable through SHA-1.

### Delegate to an external BFD daemon

Rejected for the same reason as ADR-0067.  It gives up the existing single-
owner actor, complicates status and BGP coupling, and makes standalone
rustbgpd depend on another routing suite.

### Add live, clock-scheduled rotation in the first slice

Rejected.  BIRD's signing/acceptance windows are useful, but rustbgpd's BFD
session set is currently startup-pinned.  Time schedules introduce clock-step
semantics; live keys introduce actor transaction and rollback semantics.  Both
must be justified independently if controlled restart plus overlap is not
acceptable to the named operator.

## Consequences

- Current BFD remains unauthenticated, opt-in, TTL / Hop-Limit protected, and
  behaviorally unchanged.
- The project records the shared-IXP-LAN threat without turning a plausible
  concern into speculative feature code.
- BIRD is the only current standards-shaped open-source target; no FRR auth
  compatibility claim is made from configuration names or type numbers.
- A future implementation has a bounded path through the existing codec,
  session, actor, config, and operator layers, including exact replay and
  restart requirements.
- Live rollover, additional BFD modes, link-local, and other BFD breadth remain
  separate demand-gated decisions.

## Verification

This is a documentation-only decision.  The load-bearing regression rule is
**N/A**: no production behavior, test, gate, config schema, dependency, or
interop harness changes in this ADR.

## References

- [RFC 5880 - Bidirectional Forwarding Detection](https://www.rfc-editor.org/rfc/rfc5880.html)
- [RFC 5880 Section 6.7 - Authentication](https://www.rfc-editor.org/rfc/rfc5880.html#section-6.7)
- [RFC 5880 Section 6.7.4 - Keyed SHA-1](https://www.rfc-editor.org/rfc/rfc5880.html#section-6.7.4)
- [Verified RFC 5880 Erratum 7083 - authenticated receive ordering](https://www.rfc-editor.org/errata/eid7083)
- [RFC 5880 Section 6.8.1 - State variables](https://www.rfc-editor.org/rfc/rfc5880.html#section-6.8.1)
- [RFC 5880 Section 9 - Security considerations](https://www.rfc-editor.org/rfc/rfc5880.html#section-9)
- [RFC 5881 - BFD for IPv4 and IPv6 single hop](https://www.rfc-editor.org/rfc/rfc5881.html)
- [BIRD 3.3.1 BFD documentation](https://bird.nic.cz/doc/bird-3.3.1.html)
- [BIRD 3.3.1 BFD packet source](https://gitlab.nic.cz/labs/bird/-/blob/e44ce31eba0e67f03b5cb5ecdcc67c9613be2d82/proto/bfd/packets.c)
- [FRR 10.7.0 BFD documentation source](https://github.com/FRRouting/frr/blob/frr-10.7.0/doc/user/bfd.rst)
- [FRR 10.7.0 BFD packet source](https://github.com/FRRouting/frr/blob/frr-10.7.0/bfdd/bfd_packet.c)
- [GoBGP 4.7.0 BFD documentation](https://github.com/osrg/gobgp/blob/v4.7.0/docs/sources/bfd.md)
- [OpenBGPD 9.1 portable source](https://github.com/openbgpd-portable/openbgpd-portable/tree/9.1)
