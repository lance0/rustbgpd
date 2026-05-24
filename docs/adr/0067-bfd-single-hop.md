# ADR-0067: Single-hop asynchronous BFD for BGP

**Status:** Accepted — implementation staged across PRs (crate → actor →
operator surface → BGP coupling → interop).
**Date:** 2026-05-24

## Context

`COMPARISON.md` marks **BFD integration** `No` for rustbgpd (`Yes` for FRR and
BIRD; **`No` for GoBGP and OpenBGPd**). BFD (RFC 5880 / RFC 5881) provides
sub-second peer-failure detection; RFC 5882 wires that detection to BGP so a
BFD-down event tears the neighbor down immediately instead of waiting out the
hold timer (typically 90 s / 180 s).

It is the highest-leverage remaining liveness feature: a **differentiator vs
GoBGP** (the other gRPC-first daemon, which also lacks it), it pairs with the
unicast FIB/ECMP work just shipped (ADR-0061, ADR-0066 — fast detect → fast
reconverge), and it does **not** violate the non-goals (BFD is a BGP liveness
helper, not a routing protocol).

There is no in-kernel single-hop BFD on Linux, and depending on FRR's `bfdd` is
a non-starter for a standalone daemon. In-process is the only sensible path —
and a **no-GC in-process BFD is a genuine Rust selling point vs Go**, where GC
pause jitter under load can stretch a transmit interval past the detection
window and cause false flaps.

## Decision

Implement **single-hop asynchronous BFD** for BGP, in-process, as a sans-IO
state machine driven by a dedicated actor task, with a full operator surface
(gRPC + CLI + events + metrics) and RFC 5882 coupling (strict + non-strict),
**opt-in per neighbor / peer-group**.

### Scope (v1)

- **Single-hop async** BFD (RFC 5880 control packets, RFC 5881 single-hop
  encapsulation), **demand bit clear** (asynchronous mode only).
- **Address families:** IPv4 and IPv6 **global**. Static neighbors only.
- **Full operator surface** before any behavior change (see ordering below).
- **RFC 5882 coupling:** both non-strict (BFD down tears an established session
  down early) and strict (BGP is held from establishment until BFD is up).

### Ordering principle — observability before behavior

BFD sessions become inspectable via metrics → gRPC / CLI / events **before**
RFC 5882 coupling is allowed to tear BGP down. An operator can watch BFD reach
Up and flap on a live network with zero BGP impact, building confidence in the
timing before arming the teardown. The staged delivery is:

1. **Pure crate** (`crates/bfd`) — codec + sans-IO session FSM, unit-tested with
   synthetic time, no sockets.
2. **Actor + config + status** — sessions run on real sockets and report Up/Down
   via a status `watch` channel + Prometheus metrics, but do **not** affect BGP.
3. **Operator surface** — gRPC `GetBfdSessions`, `rustbgpctl bfd`, events.
4. **BGP coupling** (RFC 5882) — behavior change, config-gated.
5. **Interop (M51) + docs** — FRR `bfdd` cross-check, `COMPARISON.md` flip.

This ADR lands with slice 2 (the actor), not at the end, so the design record
precedes the behavior change.

### Sans-IO crate + actor split

The codec (`crates/bfd/src/packet.rs`) and session FSM
(`crates/bfd/src/session.rs`) are **pure** — time is an input, never read
internally; the FSM emits `Action`s (`SendPacket`, `StateChanged`, timer
arm/stop) rather than performing I/O. This mirrors the existing `crates/wire`
(codec) and `crates/fsm` (the BGP FSM is already a sans-IO Event/Action machine)
precedents, and makes the timing-critical logic deterministically testable
without sockets or a clock.

`Session::new` returns `Result<_, SessionError>` (a zero local discriminator is
a configuration error, not a panic). Reception enforces the RFC 5880 §6.8.6
**Your Discriminator** demultiplexing rules: once a session has a remote
discriminator, packets carrying a mismatched non-zero Your Discriminator are
discarded rather than acted on.

The **actor** (`src/bfd_runtime.rs`, templated on `src/fib_runtime.rs`) is the
**sole owner** of discriminators, sockets, the real per-session timers, and
session status. Nothing else in the daemon manages per-session BFD timers. It
runs a single task that `select!`s (biased on a `CancellationToken`) over the
shared per-AF receive sockets and a single min-deadline `BinaryHeap` timer set
covering every session's transmit and detection deadlines, with per-(peer, kind)
epoch invalidation so re-armed timers retire stale heap entries.

### Sockets

One receive socket per AF bound to UDP **3784** (RFC 5881 §4), transmit from an
ephemeral source port. Outgoing packets set **TTL / Hop-Limit = 255**; received
packets are **discarded unless TTL / Hop-Limit == 255** (RFC 5881 §5, the
GTSM-style single-hop guard — load-bearing). The TTL/Hop-Limit is read from
`recvmsg` ancillary data (`IP_RECVTTL` / `IPV6_RECVHOPLIMIT`). The
`socket2::Socket` fd is registered with tokio `AsyncFd` and read via
`nix::sys::socket::recvmsg` — this is why `nix` is added to the workspace deps
with the **`uio`** feature (it gates `recvmsg` / `ControlMessageOwned` /
`cmsg_space!`).

### Timer defaults and floor

Profile defaults: `min_tx_interval` = 300 ms, `min_rx_interval` = 300 ms,
`multiplier` = 3 (≈900 ms detection). Validation enforces a **floor of 100 ms**
on the intervals and a **minimum multiplier of 2**. The floor is deliberately
conservative — false flaps are worse than being slightly slower to detect, and
the spike (below) showed ample timer headroom; the floor can be lowered later if
a deployment justifies it.

### AdminDown on teardown

On actor shutdown — and, in the coupling slice, on per-session disable / delete
— the session transitions to **AdminDown** and emits a final control packet with
State = AdminDown (RFC 5880 §6.8.16) before the socket closes, so the peer goes
Down promptly instead of waiting out its own detection timer.

### RFC 5882 BGP coupling (slice 4)

`PeerManager` expresses the **desired BFD session set** (a declarative input the
actor consumes) and consumes `BfdStateChange` events; the actor never learns BGP
internals. This keeps the actor as the sole session owner while letting BGP
drive which sessions should exist.

- **Non-strict:** BFD **down** → `PeerHandle::stop` (FSM `ManualStop` →
  session down), i.e. teardown **before** the hold timer expires. BFD **up**
  clears the BFD hold and the existing reconnect path proceeds.
- **Strict:** `add_peer` currently spawns **and immediately starts** the
  `PeerHandle`. Strict mode requires splitting that into **create managed peer →
  register BFD session → start BGP only after BFD reaches Up**. The
  `ManagedPeer` carries the `strict` flag and withholds BGP establishment until
  the first `BfdStateChange { up }`. This is a clean lifecycle refactor, not a
  bolt-on flag check.

### Config

```toml
[[bfd_profiles]]
name = "fast"
min_tx_interval = 300   # ms, floor 100
min_rx_interval = 300   # ms, floor 100
multiplier = 3          # min 2

[[neighbors]]
# ...
[neighbors.bfd]
profile = "fast"
strict = false
```

`Neighbor.bfd` and `PeerGroupConfig.bfd` are `Option<BfdConfig>`, modelled on
`tcp_ao: Option<TcpAoConfig>`; peer-group inheritance uses the existing resolve
path (a neighbor's own `bfd` wins, else its peer-group's). Validation checks
that the referenced profile name is defined and that the interval/multiplier
bounds hold, mirroring the peer-group-reference validation.

## Consequences

- Sub-second BGP failure detection, opt-in and off by default; in-process with
  no GC jitter.
- The actor is the single owner of all BFD session state — no split-brain timer
  ownership between BFD and BGP.
- Behavior is staged behind observability: metrics and the gRPC/CLI surface land
  before any BFD-driven BGP teardown exists.
- Validation: deterministic FSM + codec unit tests (no time, no sockets);
  config parse/validation tests; a privileged netns test (two actors reach Up,
  dropping traffic drives Down within the detection window, TTL≠255 is rejected);
  coupling-logic unit tests with fakes; and **M51** containerlab interop against
  FRR with `bfdd = yes` (BGP + BFD Up, induced failure drops BGP faster than the
  hold timer, recovery reconnects, asserted via both `vtysh show bfd peers` and
  `GetBfdSessions`).

### Spike findings (host loopback, throwaway, 2026-05-24)

- `AsyncFd` + `nix::recvmsg` + `ControlMessageOwned` reads received TTL
  (`Ipv4Ttl`) / hop-limit (`Ipv6HopLimit`) and the RX interface index;
  `socket2` sets TTL/hop-limit 255. **`nix` needs the `uio` feature.**
- Timer precision: a 300 ms interval under CPU load held **max jitter 0.61 ms,
  avg 0.21 ms** over 20 samples — ample margin for a 300 ms × 3 detection
  window. No timer concern.
- **IPv6 link-local / unnumbered → deferred to v1.1.** The BGP side cannot peer
  over link-local today: `Neighbor` has no interface field, the address parses
  as a bare `IpAddr` (no `%scope`), and `resolve_neighbor` builds an unscoped
  `SocketAddr`. Link-local BFD first needs link-local **BGP** peering (a shared
  neighbor interface field + scoped connect) — a separate feature. The BFD-side
  mechanics (scope_id TX, `PKTINFO` ifindex RX) are already proven, so it is a
  small add once link-local BGP lands. **v1 ships IPv4 + IPv6 global.**

## Deferred (explicit non-scope)

- **Multihop BFD** (RFC 5883).
- **Echo mode** and **demand mode**.
- **Authentication** (RFC 5880 §6.7).
- **C-bit / GR-aware** control-plane-independence nuance.
- **Static-route BFD tracking** and **dynamic-neighbor (inbound-promoted) BFD** —
  static neighbors only in v1.
- **IPv6 link-local / unnumbered** peering → **v1.1** (gated on link-local BGP
  peering, per the spike).
- **Hardware / offload.**

## Alternatives considered

- **Depend on FRR `bfdd`** — rejected; couples a standalone daemon to FRR and
  forfeits the no-GC in-process advantage.
- **Couple BFD to BGP before exposing it** — rejected; ordering observability
  before behavior lets operators validate timing with zero BGP risk first.
- **BGP-side BFD timer ownership** — rejected; the actor owns all session state
  to avoid split-brain timers across two tasks.
- **50 ms timer floor** — rejected as too aggressive for v1; false flaps are
  worse than slightly slower detection. Floor set at 100 ms, revisable later.
