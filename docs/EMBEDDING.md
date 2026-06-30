# Embedding rustbgpd — the Rust BGP library map

rustbgpd is not one crate; it is a layered workspace. The bottom layer is a
pure, zero-dependency BGP message codec (`rustbgpd-wire`) that is independently
publishable and consumable by *any* Rust project — monitor, analyzer, test
harness, MRT reader, k8s sidecar, SDN controller — without linking the daemon.

This document is the contract for embedders: which crate to depend on, what the
`pub use` boundary is, and what a minimal consumer looks like. It is the
reference for the publish-and-adoption plan (see the companion strategy memo).

---

## 1. Crate map and publish status

| Crate                    | Published? | Depends on (internal)              | Deps (external)            | Stability target | Role for embedders |
|--------------------------|-----------|-----------------------------------|----------------------------|------------------|--------------------|
| `rustbgpd-wire`          | **Yes** (crates.io, latest 0.13.0) | none (internal)            | `bytes`, `thiserror`      | **Stable codec** | The one to link. Pure encode/decode. |
| `rustbgpd-fsm`           | Staged (decoupled `0.1.0`) | `rustbgpd-wire`            | `thiserror`, `bytes`      | Publish next     | Pure RFC 4271 FSM; no I/O. |
| `rustbgpd-rpki`          | No (`publish = false`) | `rustbgpd-wire`            | `tokio`, `tracing`, `smallvec` | After fsm        | VRP table + RTR client. |
| `rustbgpd-rib`           | No           | wire, policy, telemetry, rpki     | `prefix-trie`, `ipnet`, ... | Later            | Adj/Loc-RIB; heavier. |
| `rustbgpd-policy`        | No           | wire                              | —                          | Later            | Import/export policy. |
| `rustbgpd-transport`     | No           | wire, fsm, rib, rpki, policy, telemetry, bmp | `tokio`, `socket2`, ... | Later (daemon-tier) | Async session runtime. |
| `rustbgpd-api`           | No           | (codegen)                         | `tonic`, `prost`           | Never as a lib   | gRPC server types. |
| `rustbgpd-bmp`           | No           | telemetry                         | `tokio`                    | After rib        | RFC 7854 BMP export. |
| `rustbgpd-mrt`           | No           | wire, rib                         | `flate2`, `chrono`         | After rib        | RFC 6396 dump export. |
| `rustbgpd-evpn`          | No           | (internal)                        | —                          | Daemon-tier      | EVPN origination. |
| `rustbgpd-evpn-linux`    | No           | (internal)                        | `rtnetlink`, `nix`         | Never (Linux-specific) | Kernel dataplane. |
| `rustbgpd` (daemon bin)  | No (`publish = false`) | all                            | —                          | N/A              | The daemon. Not a library. |

**Publish order and why:** `wire` → `fsm` → `rpki`. The dependency DAG forces
this: `fsm` depends only on `wire`; `rpki` depends only on `wire`; `rib`
depends on `wire + policy + telemetry + rpki`. Publishing in this order means
each published crate has only *already-published* (or external) dependencies,
which is a hard crates.io requirement. `fsm` before `rpki` because the fsm is
the smaller, purer, and more broadly useful building block — a test harness or
a minimal speaker needs the fsm but not the RPKI table. See §4 for the full
rationale.

---

## 2. `rustbgpd-wire` — the codec layer

### 2.1 What you get

The wire crate is a pure codec: encode/decode of BGP messages to/from `bytes`
buffers. No `unsafe`, no panics on malformed input (all paths return `Result`),
no async runtime, no sockets. Two external dependencies only: `bytes` and
`thiserror`.

Public surface (re-exported at crate root — `crates/wire/src/lib.rs`):

- **Entry points:** `decode_message(&mut Bytes, max_len: u16) -> Result<Message, DecodeError>`,
  `encode_message(&Message) -> Result<BytesMut, EncodeError>`,
  `peek_message_length(&Bytes) -> Option<usize>` (transport framing).
- **`Message`** enum: `Open`, `Update`, `Keepalive`, `Notification`, `RouteRefresh`.
- **`OpenMessage`** — capabilities negotiation; `Capability` enum (MP-BGP,
  4-octet AS, Add-Path, GR/LLGR, ORF, BGP Roles, Extended Messages, ...).
- **`UpdateMessage`** — raw wire framing + `parse()` → `ParsedUpdate`
  (decoded NLRI + `Vec<PathAttribute>`).
- **`PathAttribute`** — 14 typed variants + `Unknown` pass-through (`AsPath`,
  `NextHop`, `Communities`, `MpReachNlri`, `LargeCommunities`, `PmsiTunnel`,
  `OnlyToCustomer`, ...).
- **`Prefix`** (`V4(Ipv4Prefix)` / `V6(Ipv6Prefix)`), `NlriEntry`, Add-Path IDs.
- **`Afi` / `Safi`** — IANA address-family identifiers.
- **EVPN** (`EvpnRoute`/`EvpnRouteKey`, Types 1–5), **FlowSpec** (`FlowSpecRule`),
  **VPNv4/v6** (`vpn` module), **BGP-LS** (`bgpls` module), **ORF** (`orf` module),
  **PMSI Tunnel**, **Route Distinguisher**.
- **Well-known community constants** (`COMMUNITY_NO_EXPORT`, `COMMUNITY_BLACKHOLE`,
  `COMMUNITY_GRACEFUL_SHUTDOWN`, `COMMUNITY_LLGR_STALE`, ...).
- **`DecodeError` / `EncodeError`** via `thiserror`.
- **`UpdateMessage::build` / `try_build`** — construct a wire UPDATE from typed
  components; `try_build` is the fallible counterpart (returns `EncodeError`).

### 2.2 `pub use` boundary

The crate root re-exports the primary types. Modules (`attribute`, `evpn`,
`bgpls`, `vpn`, `orf`, `flowspec`, `capability`, ...) are also `pub mod`, so
embedders can reach internal helpers, but the canonical import path is the crate
root:

```rust
use rustbgpd_wire::{
    Afi, Capability, DecodeError, EncodeError, Message, OpenMessage,
    Safi, decode_message, encode_message,
};
```

The README (`crates/wire/README.md`) is the rendered crate documentation and is
the source of the supported-RFC table.

### 2.3 Semver policy

The wire crate follows the Cargo/semver convention with a documented wire-specific
policy (`docs/RELEASE_CHECKLIST.md` §"Wire crate semver"):

- **Patch**: bug fixes, stricter validation, docs/test improvements.
- **Minor**: new message types, attributes, helper methods, additive API changes.
- **Major**: breaking API changes, changed method signatures, enum shape changes.

**The 0.13.0 breaking change and `#[non_exhaustive]`:** Adding `Afi::BgpLs` and
`Safi::BgpLs` / `Safi::BgpLsVpn` variants to the `Afi`/`Safi` enums is a breaking
change because those enums are **not** `#[non_exhaustive]` (verified:
`crates/wire/src/capability.rs:8-66`). The 0.12.0 → 0.13.0 bump correctly went to
a major (0.x major = minor-number bump). The README and CHANGELOG call out that
exhaustive downstream matches must add arms.

**Forward fix (first patch after publish):** Add `#[non_exhaustive]` to `Afi`
and `Safi` (and any other IANA-registry-backed enum that can grow, e.g.
`PmsiTunnelType` already uses an `Other(u8)` catch-all; `NotificationCode` is a
candidate). Adding `#[non_exhaustive]` to an *existing* exhaustive enum is
itself a breaking change, so this must land in the *next* major bump (0.14.0 or
1.0.0), *not* a patch. Once marked, future IANA additions become minor bumps.
See §5 of the strategy memo.

---

## 3. Minimal examples

### 3.1 Decode an UPDATE (codec-only — the canonical embedder)

This is the "MRT reader / monitor / analyzer" consumer. Links only
`rustbgpd-wire`.

```toml
# Cargo.toml
[dependencies]
rustbgpd-wire = "0.13"
bytes = "1"
```

```rust
use bytes::Bytes;
use rustbgpd_wire::{decode_message, MAX_MESSAGE_LEN, Message};

/// Decode one BGP message from a raw byte stream (e.g. from a TCP socket or
/// an MRT record body) and print the IPv4 NLRI it carries.
fn handle(raw: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
    let mut buf = Bytes::from(raw);
    let msg = decode_message(&mut buf, MAX_MESSAGE_LEN)?;
    if let Message::Update(update) = msg {
        let parsed = update.parse(
            true,  // 4-octet AS negotiated
            false, // Add-Path not negotiated for body NLRI
            &[],   // Add-Path families for MP NLRI (empty = none)
        )?;
        for entry in &parsed.announced {
            println!("announced: {}", entry.prefix);
        }
        for attr in &parsed.attributes {
            println!("attribute: {attr:?}");
        }
    }
    Ok(())
}
```

### 3.2 Build and encode an OPEN

```rust
use std::net::Ipv4Addr;
use rustbgpd_wire::{encode_message, Afi, Capability, Message, OpenMessage, Safi};

let open = OpenMessage {
    version: 4,
    my_as: 65000,
    hold_time: 90,
    bgp_identifier: Ipv4Addr::new(10, 0, 0, 1),
    capabilities: vec![
        Capability::FourOctetAs { asn: 65000 },
        Capability::MultiProtocol { afi: Afi::Ipv4, safi: Safi::Unicast },
        Capability::RouteRefresh,
    ],
};
let bytes = encode_message(&Message::Open(open)).expect("encode OPEN");
```

### 3.3 Build a session (codec + FSM — the "minimal speaker" consumer)

This is the "k8s sidecar / SDN controller / test harness" consumer. Links
`rustbgpd-wire` + `rustbgpd-fsm`. The FSM is pure: it produces `Action`s from
`Event`s; the *embedder* owns the TCP socket and the timers. This is the
intentional split (ADR-0002: inherent methods, no I/O in the FSM).

```toml
# Cargo.toml  (after fsm is published)
[dependencies]
rustbgpd-wire = "0.13"
rustbgpd-fsm = "0.1"
bytes = "1"
tokio = { version = "1", features = ["net", "io-util", "time", "rt"] }
```

```rust
use std::net::Ipv4Addr;
use rustbgpd_wire::{Afi, Safi, encode_message, Message};
use rustbgpd_fsm::{PeerConfig, Session, Event, Action, SessionState};

// 1. Configure the peer (4-byte AS, IPv4 unicast, hold 90s).
let cfg = PeerConfig {
    local_asn: 65000,
    remote_asn: 65001,
    local_router_id: Ipv4Addr::new(10, 0, 0, 1),
    hold_time: 90,
    connect_retry_secs: 120,
    families: vec![(Afi::Ipv4, Safi::Unicast)],
    graceful_restart: false,
    gr_restart_time: 0,
    llgr_stale_time: 0,
    add_path_receive: false,
    add_path_send: false,
    add_path_send_max: 0,
    local_role: None,
    strict_role: false,
    prefix_orf_receive: false,
    disable_ipv4_unicast: false,
};

// 2. Create the FSM. Starts in Idle.
let mut sm = Session::new(cfg);

// 3. Drive it: operator starts the session -> FSM says "connect + start timers".
for action in sm.handle_event(Event::ManualStart) {
    match action {
        Action::InitiateTcpConnection => { /* embedder opens a TCP socket */ }
        Action::StartTimer(t, secs) => { /* embedder arms a tokio timer */ }
        Action::SendOpen(open) => {
            let bytes = encode_message(&Message::Open(open))?;
            // embedder writes bytes to the TCP stream
        }
        _ => {}
    }
}

// 4. On peer OPEN received: feed BgpOpen(msg) -> FSM validates, emits SendKeepalive.
//    On KEEPALIVE received in OpenConfirm: -> Established.
//    The embedder maps Action::SendKeepalive to encode_message(&Message::Keepalive).
assert_eq!(sm.state(), SessionState::Connect); // until TCP confirms
```

The FSM does not touch the network. It is `(State, Event) -> (State, Vec<Action>)`.
This makes it trivially testable and lets a sidecar plug in any transport
(TCP, TLS, a Unix socket for tests, a virtual link in a simulator).

### 3.4 What a "prefixd-class" consumer links

A route-injection controller (the rustbgpd beachhead — an automation controller
that originates and withdraws prefixes) has two viable shapes:

**Shape A — link the daemon's gRPC API (no codec).** The controller is a
separate process that talks to `rustbgpd` over gRPC (`RibService.AddRoutes`,
`DeleteRoutes`, `WatchEvents`). This is what `examples/event-bridge/` already
demonstrates — it links only `rustbgpd-api` (the generated gRPC client types)
and streams events out as JSON. This is the *recommended* shape for production:
the daemon owns the sessions and the RIB; the controller owns the intent.
Links: `rustbgpd-api` + `tonic` + `tokio`. No codec, no FSM.

**Shape B — link the codec + FSM and speak BGP directly.** A sidecar that does
not want a full daemon in the loop (e.g. a minimal speaker in a constrained
k8s pod) links `rustbgpd-wire` + `rustbgpd-fsm` and owns one or a few sessions.
It does *not* get a RIB or best-path — it is a speaker, not a router. This is
the gap Cilium fills by embedding GoBGP today. Links: `rustbgpd-wire` +
`rustbgpd-fsm` + `tokio`. If it needs origin validation, add `rustbgpd-rpki`
(once published).

---

## 4. Which crate to publish next, and why

**Order: `wire` → `fsm` → `rpki` → (rib, bmp, mrt, policy later).**

1. **`rustbgpd-wire` (publish 0.13.0 now).** Already on crates.io; the 0.13.0
   breaking bump (BGP-LS Afi/Safi + fallible `try_build`) is staged in
   `crates/wire/Cargo.toml` and the CHANGELOG. This is the foundation — nothing
   else can publish before it because every internal crate depends on it.

2. **`rustbgpd-fsm` (publish next, as a decoupled `0.1.0`).** Why:
   - It depends *only* on `rustbgpd-wire` + `thiserror` + `bytes`. Zero
     daemon-tier coupling. It can publish the moment `wire` is on crates.io.
   - It is the smallest, purest building block a second consumer needs. A test
     harness, a fuzzer, a minimal speaker, and an SDN controller all want "the
     RFC 4271 state machine" without a RIB.
   - API stability required: `Session`, `Event`, `Action`, `SessionState`,
     `NegotiatedSession`, `PeerConfig` must be stable. `PeerConfig` is a public
     struct with public fields — adding a field is a breaking change unless it
     is `#[non_exhaustive]` or gets a `Default` + builder. Mark
     `PeerConfig` and `NegotiatedSession` `#[non_exhaustive]` *before* the
     first publish so future capability additions are minor bumps. `Event` and
     `Action` are enums that will grow (new RFCs add new events/actions) —
     mark them `#[non_exhaustive]` too.

3. **`rustbgpd-rpki` (publish after fsm).** Why:
   - It depends only on `rustbgpd-wire` + `tokio` + `tracing` + `smallvec`.
     No `rib`/`policy` edge.
   - It is the natural third publish because a route-injecting sidecar that
     wants origin validation needs exactly `wire + fsm + rpki` — nothing else.
   - API stability required: `VrpTable`, `VrpEntry`, `RtrClient`,
     `VrpManager`, `validate(prefix, asn)`. The `Arc<VrpTable>` snapshot pattern
     is already lock-free and stable. The RTR client API (`RtrClient`) is
     async and tokio-coupled — document the runtime requirement.

4. **Later: `rib`, `bmp`, `mrt`, `policy`.** These pull in heavier deps
   (`prefix-trie`, `ipnet`, `flate2`, `chrono`) and have more churn. Publish
   only when there is a concrete external consumer asking for them. The `rib`
   in particular exposes best-path selection, which is a large, still-evolving
   surface — it is not ready to be a stable external API in alpha.

5. **Never publish as a library: `transport`, `api`, `evpn`, `evpn-linux`,
   the daemon binary.** `transport` is the daemon's async session runtime and
   is tightly coupled to the full stack. `api` is generated gRPC types.
   `evpn-linux` is Linux-kernel-specific. The daemon is a binary.

---

## 5. Target consumers beyond prefixd

| # | Consumer | What it does today | What it links from rustbgpd | API surface it needs | Honest read |
|---|----------|-------------------|-----------------------------|----------------------|--------------|
| 1 | **BGP test harness / fuzzer** (à la GoBGP's `internal/testing`, or a Rust peer for FRR interop CI) | Replays PCAPs/MRT, speaks BGP to a device under test, asserts on received UPDATEs | `rustbgpd-wire` (decode/encode), `rustbgpd-fsm` (drive a peer) | `decode_message`, `encode_message`, `Message`/`ParsedUpdate`, `Session::handle_event` | **Highest-leverage, lowest-friction.** Pure codec + pure FSM. No network state, no RIB. This is the crate's natural first friend — we should ship one in-tree as `examples/peer-loop/` to prove the embedding story. |
| 2 | **MRT route collector / analyzer** (à la BGPKIT-parser use case, but with *encode* too) | Reads RFC 6396 dumps, decodes UPDATEs, builds reports; some also synthesize test traffic | `rustbgpd-wire` for decode; optionally `rustbgpd-mrt` later for the dump container | `decode_message`, `ParsedUpdate`, `PathAttribute`, `Prefix`, EVPN/FlowSpec/BGP-LS NLRI types | **Strong fit.** The wire crate already decodes everything BGPKIT-parser parses *plus* BGP-LS, ORF, PMSI, OTC. The gap is the MRT container — `rustbgpd-mrt` closes it but is not yet published. |
| 3 | **k8s BGP sidecar / minimal speaker** (the Cilium-embeds-GoBGP niche, in Rust) | Advertises pod/service CIDRs to a top-of-rack router; needs a *speaker*, not a router | `rustbgpd-wire` + `rustbgpd-fsm` (+ `rustbgpd-rpki` for origin validation) | `Session`, `PeerConfig`, `Action`, `encode_message`, `VrpTable` | **Real but hard.** This is GoBGP's library-reach moat: Cilium embeds the full GoBGP library (not just the codec) to get a session runtime + RIB + policy. rustbgpd offers only codec+FSM as a library today; the sidecar would have to own the RIB-less "speaker" path itself. Honest: we are not displacing Cilium's GoBGP embedding in 2026; we are the option for a *Rust-native* sidecar that wants no CGo and a smaller blast radius. |
| 4 | **RPKI validator / RTR cache client** (à la Routinator consumer, or a VRP-driven policy gate) | Maintains a VRP table from one or more RTR caches; validates origins | `rustbgpd-rpki` (`VrpTable`, `RtrClient`, `VrpManager`), `rustbgpd-wire` (`RpkiValidation`) | `VrpTable::validate`, `RtrClient` async session, `VrpManager` merge | **Good fit once `rpki` publishes.** The `RpkiValidation` enum already lives in `wire` (shared by rib/policy/transport), so the validation-state type is already stable. The RTR client is the novel value. |
| 5 | **BMP monitor / telemetry sink** (à la OpenBMP, or a Rust BMP collector) | Receives RFC 7854 BMP messages, decodes per-peer UPDATEs, exports metrics | `rustbgpd-wire` (decode embedded UPDATEs), `rustbgpd-bmp` later | `decode_message`, `PathAttribute`, `MpReachNlri` | **Medium.** BMP message framing is small; the value is the embedded UPDATE decode, which `wire` already does. `rustbgpd-bmp` is the container/framing; publish it once a collector asks. |

---

## 6. Becoming the de facto Rust BGP codec — what's missing vs GoBGP's library reach

GoBGP's library moat is not its codec; it is that the *whole daemon* is a Go
library (`github.com/osrg/gobgp`), so Cilium imports the package and gets a
session runtime + RIB + policy + gRPC server in-process. rustbgpd's
complementary moat is the opposite and narrower: a *pure, memory-safe,
zero-dep codec* that any Rust project can link without dragging in a runtime.

To be the de facto Rust BGP codec, the concrete gaps:

1. **Make the enums forward-compatible.** Mark `Afi`, `Safi`, `Event`, `Action`,
   `PathAttribute`, `Capability`, `Message`, `NotificationCode` and any
   IANA-registry-backed enum `#[non_exhaustive]` in the next major bump. Today,
   every new AFI/SAFI is a breaking change — that is a tax on adopters and on
   us. (Verified: none are `#[non_exhaustive]` today.) This is the single
   highest-leverage stability fix.
2. **Ship an in-tree embedder as proof.** Add `examples/peer-loop/`: a ~150-line
   binary that links `wire + fsm`, opens one TCP session to a configured peer,
   drives the FSM, and prints every received UPDATE. This is the "it works"
   receipt for consumers #1 and #3. The `event-bridge` example already proves the
   gRPC-client shape; this proves the library-embedding shape.
3. **Add a `tokio_util::codec::Decoder/Encoder` impl.** ADR-0002 notes the
   transport layer integrates via `decode_message`/`encode_message` inside a
   `tokio_util::codec::Decoder`. Publish that `Decoder`/`Encoder` *in the wire
   crate* (gated on a `tokio-codec` feature that pulls `bytes` only — no full
   tokio) so any async consumer gets framed decode for free. This is the
   "battery-included" ergonomic that bgp-rs/zettabgp lack.
4. **Run `cargo-semver-checks` in CI** against the published wire crate so
   accidental breaking changes are caught before publish. Add to
   `.github/workflows/ci.yml` on the wire crate path.
5. **docs.rs is the storefront.** Ensure `cargo doc` is warning-clean (already
   a release gate) and that the README's supported-RFC table stays the landing
   page. Add per-type examples in doc-comments for `decode_message`,
   `encode_message`, `UpdateMessage::parse`, `UpdateMessage::try_build`.
6. **Be honest about what the codec is *not*.** It is not a session runtime,
   not a RIB, not a router. The embedder that needs a full in-process router
   (Cilium) cannot get it from rustbgpd as a library today. The embedder that
   needs a *codec* or a *pure FSM* — monitors, analyzers, test harnesses,
   minimal speakers, RPKI validators — can, and in Rust, with memory safety and
   no CGo. That is the wedge.

---

## 7. File-level checklist (execution)

- [ ] `crates/wire/Cargo.toml` — bump to `0.13.0` is staged; verify
      `description`, `readme`, `keywords`, `categories` are present (they are).
- [ ] `crates/wire/src/capability.rs` — add `#[non_exhaustive]` to `Afi` (line 9)
      and `Safi` (line 37) in the *next* major bump (0.14.0 / 1.0.0), not 0.13.x.
- [ ] `crates/wire/src/lib.rs` — add `#[non_exhaustive]` audit to the enums
      listed in §6.1 above; add `tokio_util::codec` impl behind a feature.
- [ ] `crates/fsm/Cargo.toml` — remove `publish = false`; set an independent
      version (`0.1.0` decoupled, or `0.45.0` tracking workspace); add
      `description`, `readme`, `keywords`, `categories`.
- [ ] `crates/fsm/src/config.rs` — mark `PeerConfig` (line 29)
      `#[non_exhaustive]` before first publish.
- [ ] `crates/fsm/src/{event.rs,action.rs,state.rs}` — mark `Event`, `Action`,
      `SessionState` `#[non_exhaustive]` before first publish.
- [ ] `crates/rpki/Cargo.toml` — remove `publish = false`; decouple version.
- [ ] `docs/RELEASE_CHECKLIST.md` — add a "library crate publish" sub-section
      that runs `cargo semver-checks` and verifies docs.rs renders.
- [ ] `examples/peer-loop/` — new example binary linking `wire + fsm`
      (the embedding proof).
- [ ] `.github/workflows/ci.yml` — gate `cargo semver-checks` on
      `crates/wire/**` and (once published) `crates/fsm/**` path changes.
