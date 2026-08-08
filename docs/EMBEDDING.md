# Embedding rustbgpd — the Rust BGP library map

rustbgpd is not one crate; it is a layered workspace. The bottom layers are
published as daemon-independent crates: a pure BGP message codec
(`rustbgpd-wire`) and a pure RFC 4271 state machine (`rustbgpd-fsm`). They are
consumable by Rust projects — monitors, analyzers, test harnesses, MRT readers,
k8s sidecars, SDN controllers — without linking the daemon.

This document is the contract for embedders: which crate to depend on, what the
`pub use` boundary is, and what a minimal consumer looks like.

---

## 1. Crate map and publish status

<!-- BEGIN EMBEDDING CRATE MAP -->
| Package | Cargo publish | Internal normal/build path dependencies | Role |
|---------|---------------|-----------------------------------------|------|
| `birdwatcher-adapter` | Disabled | `rustbgpd-api` | Birdwatcher-compatible REST adapter backed by the daemon gRPC API. |
| `event-bridge` | Disabled | `rustbgpd-api` | Reference durable-event collector bridge. |
| `rs-config-render` | Disabled | None | Route-server configuration rendering tool. |
| `rustbgpctl` | Disabled | `rustbgpd-policy`, `rustbgpd-wire` | Thin gRPC management CLI and support library. |
| `rustbgpd` | Disabled | `rustbgpd-api`, `rustbgpd-bfd`, `rustbgpd-bmp`, `rustbgpd-event-history`, `rustbgpd-evpn`, `rustbgpd-evpn-linux`, `rustbgpd-fsm`, `rustbgpd-mrt`, `rustbgpd-policy`, `rustbgpd-rib`, `rustbgpd-rpki`, `rustbgpd-telemetry`, `rustbgpd-transport`, `rustbgpd-wire` | Daemon binary and internal assembly library. |
| `rustbgpd-api` | Disabled | `rustbgpd-event-history`, `rustbgpd-evpn`, `rustbgpd-fsm`, `rustbgpd-policy`, `rustbgpd-rib`, `rustbgpd-telemetry`, `rustbgpd-transport`, `rustbgpd-wire` | gRPC server, generated bindings, and service types. |
| `rustbgpd-bfd` | Disabled | None | Pure BFD packet codec and session state machine. |
| `rustbgpd-bmp` | Disabled | `rustbgpd-telemetry`, `rustbgpd-wire` | RFC 7854 BMP export. |
| `rustbgpd-event-history` | Disabled | `rustbgpd-telemetry` | Durable local event outbox. |
| `rustbgpd-evpn` | Disabled | `rustbgpd-wire` | EVPN VTEP domain model. |
| `rustbgpd-evpn-linux` | Disabled | `rustbgpd-evpn` | Linux netlink EVPN dataplane reconciler. |
| `rustbgpd-evpn-load` | Disabled | `rustbgpd-wire` | EVPN route-reflector benchmark load generator. |
| `rustbgpd-fsm` | Enabled | `rustbgpd-wire` | Pure RFC 4271 FSM; no I/O. |
| `rustbgpd-mrt` | Disabled | `rustbgpd-rib`, `rustbgpd-wire` | RFC 6396 MRT dump export. |
| `rustbgpd-policy` | Disabled | `rustbgpd-wire` | Import/export policy engine. |
| `rustbgpd-rib` | Disabled | `rustbgpd-bmp`, `rustbgpd-policy`, `rustbgpd-rpki`, `rustbgpd-telemetry`, `rustbgpd-wire` | Adj-RIB and Loc-RIB best-path data structures. |
| `rustbgpd-rpki` | Disabled | `rustbgpd-wire` | VRP table, RTR client, and origin validation. |
| `rustbgpd-telemetry` | Disabled | None | Prometheus metrics and structured tracing. |
| `rustbgpd-transport` | Disabled | `rustbgpd-bmp`, `rustbgpd-fsm`, `rustbgpd-policy`, `rustbgpd-rib`, `rustbgpd-rpki`, `rustbgpd-telemetry`, `rustbgpd-wire` | Async TCP session runtime. |
| `rustbgpd-wire` | Enabled | None | Pure BGP message encode/decode. |
<!-- END EMBEDDING CRATE MAP -->

All Cargo workspace packages are listed. Internal dependencies include normal and build dependencies, including target-specific dependencies; dev dependencies are excluded.

Only `rustbgpd-wire` and `rustbgpd-fsm` are registry-published releases from
this workspace. `Disabled` means this repository's package manifest sets
`publish = false`; it makes no claim about unrelated registry packages with a
similar name. These workspace packages can still be consumed through git or
path dependencies, including from outside this repository. A consumer that
needs the daemon's gRPC surface can instead generate a client from the proto
(§3.4).

This map records the current workspace topology, not a publication sequence.
Notably, `rustbgpd-rib` depends on `rustbgpd-bmp`; §4 discusses future
publication candidates and the gates that would apply.

---

## 2. `rustbgpd-wire` — the codec layer

### 2.1 What you get

The wire crate is a pure codec: encode/decode of BGP messages to/from `bytes`
buffers. No `unsafe`, no panics on malformed input (all paths return `Result`),
no async runtime, no sockets. Two external dependencies only: `bytes` and
`thiserror`.

Public surface (re-exported at crate root — `crates/wire/src/lib.rs`):

- **Entry points:** `decode_message(&mut Bytes, max_message_len: u16) -> Result<Message, DecodeError>`,
  `encode_message(&Message) -> Result<BytesMut, EncodeError>`,
  `peek_message_length(&[u8], max_message_len: u16) -> Result<Option<u16>, DecodeError>`
  (transport framing: `Ok(None)` means "header not yet buffered").
- **`Message`** enum: `Open`, `Update`, `Keepalive`, `Notification`, `RouteRefresh`.
- **`OpenMessage`** — capabilities negotiation; `Capability` enum (MP-BGP,
  4-octet AS, Add-Path, experimental Paths-Limit via `PathsLimitFamily`,
  GR/LLGR, ORF, BGP Roles, Extended Messages, ...).
- **`UpdateMessage`** — raw wire framing + `parse()` → `ParsedUpdate`
  (decoded NLRI + `Vec<PathAttribute>`).
- **`PathAttribute`** — typed variants + `Unknown` pass-through (`AsPath`,
  `Aggregator`, `NextHop`, `Communities`, `MpReachNlri`, `LargeCommunities`,
  `PmsiTunnel`, `OnlyToCustomer`, ...).
- **`Prefix`** (`V4(Ipv4Prefix)` / `V6(Ipv6Prefix)`), `NlriEntry`, Add-Path IDs.
- **`Afi` / `Safi`** — IANA address-family identifiers.
- **EVPN** (`EvpnRoute`/`EvpnRouteKey`, Types 1–5; route keys implement `Ord`),
  **FlowSpec** (`FlowSpecRule`),
  **VPNv4/v6** (`vpn` module), **BGP-LS** (`bgpls` module), **ORF** (`orf` module),
  **PMSI Tunnel**, **Route Distinguisher** (`Display`/`FromStr` for the three
  structured RFC 4364 forms and the exact `0x<16-hex-digits>` display fallback
  for unknown RD types).
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

**Registry growth is no longer breaking.** As of the published `0.15.0`, every
enum that tracks an IANA/RFC registry — `Capability`, `PathAttribute`,
`Afi`/`Safi`, `Message`/`MessageType`, `NotificationCode`, and the EVPN,
FlowSpec, ORF, PMSI, and error enums — is `#[non_exhaustive]`. Match them with
a wildcard arm and a new capability code, path attribute, or AFI/SAFI arrives
in a minor release without a semver-major break. Closed-by-construction sets
(`Origin`, `AsPathSegment`, `Prefix`, `AddPathMode`, `ErrorDisposition`,
`RpkiValidation`) stay exhaustively matchable on purpose. `crates/wire/README.md`
carries the full split under "Enum exhaustiveness".

**The 0.16.0 release** is additive at the API level, but **decode
acceptance or type classification changed in six places** — bytes that decoded
under 0.15.0 may now be rejected or typed differently. `crates/wire/README.md`
carries the itemized list under "0.16.0 compatibility note"; diff exactly that
list before you upgrade a consumer that asserts on acceptance or typed
variants. Consumers comparing decoded values must also account for RFC 8092
Large Community duplicate normalization, which keeps the first occurrence.
Separately, `RouteDistinguisher::from_str` now accepts the displayed
`0x<16-hex-digits>` fallback for unknown RD types and the non-exhaustive
`RouteDistinguisherParseError` gains `InvalidHexFallback(String)`. That is an
additive text-parser acceptance and API change, not a seventh binary
wire-decode change.

---

## 3. Minimal examples

### 3.1 Decode an UPDATE (codec-only — the canonical embedder)

This is the "MRT reader / monitor / analyzer" consumer. Links only
`rustbgpd-wire`.

```toml
# Cargo.toml
[dependencies]
rustbgpd-wire = "0.17.0"
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
# Cargo.toml
[dependencies]
rustbgpd-wire = "0.17.0"
rustbgpd-fsm = "0.3.1"
bytes = "1"
tokio = { version = "1", features = ["net", "io-util", "time", "rt"] }
```

```rust
use std::net::Ipv4Addr;

use rustbgpd_fsm::{Action, Event, PeerConfig, Session, SessionState};
use rustbgpd_wire::{Afi, Message, Safi, encode_message};

fn start_session() -> Result<Session, Box<dyn std::error::Error>> {
    // 1. Configure the peer. `PeerConfig` is `#[non_exhaustive]`, so build it
    //    with the constructor and set optional fields in place.
    let mut cfg = PeerConfig::new(65000, 65001, Ipv4Addr::new(10, 0, 0, 1));
    cfg.families = vec![(Afi::Ipv4, Safi::Unicast)];

    // 2. Create the FSM. Starts in Idle.
    let mut sm = Session::new(cfg);

    // 3. Drive it: operator starts the session -> FSM says "connect + start timers".
    for action in sm.handle_event(Event::ManualStart) {
        match action {
            Action::InitiateTcpConnection => { /* embedder opens a TCP socket */ }
            Action::StartTimer(_timer, _secs) => { /* embedder arms a tokio timer */ }
            Action::SendOpen(open) => {
                let _bytes = encode_message(&Message::Open(open))?;
                // embedder writes the bytes to the TCP stream
            }
            // `Action` is `#[non_exhaustive]`: ignore what you do not drive.
            _ => {}
        }
    }

    // 4. On peer OPEN received: feed Event::BgpOpen -> the FSM validates and
    //    emits SendKeepalive. On KEEPALIVE in OpenConfirm: -> Established.
    //    The embedder maps Action::SendKeepalive to Message::Keepalive.
    assert_eq!(sm.state(), SessionState::Connect); // until TCP confirms
    Ok(sm)
}
```

The FSM does not touch the network. It is `(State, Event) -> (State, Vec<Action>)`.
This makes it trivially testable and lets a sidecar plug in any transport
(TCP, TLS, a Unix socket for tests, a virtual link in a simulator).

### 3.4 What a "prefixd-class" consumer links

A route-injection controller (the rustbgpd beachhead — an automation controller
that originates and withdraws prefixes) has two viable shapes:

**Shape A — drive the daemon over gRPC (no codec).** The controller is a
separate process that talks to `rustbgpd` over gRPC. This is the *recommended*
shape for production: the daemon owns the sessions and the RIB; the controller
owns the intent. No codec, no FSM.

External consumers do **not** link `rustbgpd-api`. That crate is `publish =
false` — it is the daemon's own generated server types and is not resolvable
from outside this repository. The supported path is to generate a client from
[`proto/rustbgpd.proto`](../proto/rustbgpd.proto), which is self-contained: it
declares package `rustbgpd.v1` and imports nothing, so no well-known-type
include path is required.

- **Rust** — `tonic-prost-build` in a `build.rs` (`compile_protos`), the same
  codegen the daemon itself uses; `tonic` + `tokio` at runtime.
- **Go** — `protoc-gen-go` + `protoc-gen-go-grpc`.
- **Python** — `grpcio-tools` (`python -m grpc_tools.protoc`).

The three services that matter for a route-injection controller:

| Service | Methods you will actually call |
|---------|-------------------------------|
| `InjectionService` | `AddPath` / `DeletePath` (unicast prefixes), `AddFlowSpec` / `DeleteFlowSpec`, `AddEvpnRoute` / `DeleteEvpnRoute` |
| `RibService` | `ListReceivedRoutes`, `ListBestRoutes`, `ListAdvertisedRoutes`, `ExplainBestPath`, `ExplainAdvertisedRoute`, `WatchRoutes`, `WatchRouteEvents` |
| `EventService` | `WatchEvents` (live stream), `SubscribeFromEvent` (durable cursor replay, §8) |

Route origination is `InjectionService`, not `RibService` — `RibService` is the
read and explain surface. [`docs/grpc-method-inventory.md`](grpc-method-inventory.md)
lists every method with its authorization tier, and its machine-readable twin
[`grpc-method-inventory.json`](grpc-method-inventory.json) is checked in CI
against the Rust source-of-truth table, so it is the authority on which methods
exist. The proto itself remains the definitive schema.

**Shape B — link the codec + FSM and speak BGP directly.** A sidecar that does
not want a full daemon in the loop (e.g. a minimal speaker in a constrained
k8s pod) links `rustbgpd-wire` + `rustbgpd-fsm` and owns one or a few sessions.
It does *not* get a RIB or best-path — it is a speaker, not a router. This is
the gap Cilium fills by embedding GoBGP today. Links: `rustbgpd-wire` +
`rustbgpd-fsm` + `tokio`. If it needs origin validation, add `rustbgpd-rpki`
once that crate is published.

---

## 4. Which crate to publish next, and why

**Status: `wire` → `fsm` are published; `rpki` is next; `rib`, `bmp`, `mrt`,
and `policy` are later.**

1. **`rustbgpd-wire` (published as `0.17.0`).** This is the
   foundation — dependent crate versions cannot publish before their wire
   dependency exists on crates.io. `0.15.0` brought `Capability::PathsLimit`
   with its `PathsLimitFamily` entry type (experimental capability code 76),
   the `Ord` implementation on `EvpnRouteKey`, and `#[non_exhaustive]` across
   the registry-tracking enums. The `0.16.0` release is additive at the API
   level with six binary decode-acceptance changes plus the separate additive
   Route Distinguisher text-parser change described in §2.3. `0.17.0` is a
   **breaking release**: `encode_evpn_nlri` now returns
   `Result<(), EncodeError>` instead of `()`. Direct callers must handle or
   propagate the result, and on `Err` the output buffer may hold a partial
   encoding and must be discarded. Three EVPN wire invariants that release
   builds previously papered over (encoding substitute bytes) now refuse to
   encode with `EncodeError::ValueOutOfRange`: a Type 5 gateway whose address
   family differs from its prefix, an EAD-per-ES route whose ethernet tag is
   not `MAX_ET`, and an EAD-per-EVI route whose ethernet tag is `MAX_ET`.
   Indirect encode paths (`MP_REACH_NLRI`/`MP_UNREACH_NLRI` via
   `UpdateMessage::try_build` / `encode_message`) surface the same routes as
   errors where they previously emitted silently altered wire bytes.
   `crates/wire/README.md` carries the itemized note under "0.17.0
   compatibility note".

2. **`rustbgpd-fsm` (published as `0.3.1`).** The `0.3.1` release keeps the
   public API backward-compatible: `PeerConfig` gains
   `min_hold_time` and `required_families`, and `PeerConfig` is
   `#[non_exhaustive]`, so external construction through `PeerConfig::new` is
   unaffected. Negotiation behavior also carries conformance fixes: the last
   duplicate Graceful Restart capability wins, and invalid OPEN identities
   are rejected. Why the FSM was the second published crate:
   - It depends *only* on `rustbgpd-wire` + `thiserror` + `bytes`. Zero
     daemon-tier coupling.
   - It is the smallest, purest building block a second consumer needs. A test
     harness, a fuzzer, a minimal speaker, and an SDN controller all want "the
     RFC 4271 state machine" without a RIB.
   - API stability required: `Session`, `Event`, `Action`, `SessionState`,
     `NegotiatedSession`, `PeerConfig` must be stable. `PeerConfig` is a public
     struct with public fields — adding a field is a breaking change unless it
     is `#[non_exhaustive]` or gets a constructor/default path. The published
     crate already has the forward-compat boundary: `PeerConfig`,
     `NegotiatedSession`, `Event`, and `Action` are `#[non_exhaustive]`.

3. **`rustbgpd-rpki` (publish next).** Why:
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
runtime-free codec with no internal-crate dependencies* that any Rust project
can link without dragging in the daemon stack.

To be the de facto Rust BGP codec, the concrete gaps:

1. **Ship an in-tree embedder as proof.** Add `examples/peer-loop/`: a ~150-line
   binary that links `wire + fsm`, opens one TCP session to a configured peer,
   drives the FSM, and prints every received UPDATE. This is the "it works"
   receipt for consumers #1 and #3. The `event-bridge` example already proves the
   gRPC-client shape; this proves the library-embedding shape.
2. **Add a `tokio_util::codec::Decoder/Encoder` impl.** ADR-0002 notes the
   transport layer integrates via `decode_message`/`encode_message` inside a
   `tokio_util::codec::Decoder`. Publish that `Decoder`/`Encoder` *in the wire
   crate* (gated on a `tokio-codec` feature that pulls `bytes` only — no full
   tokio) so any async consumer gets framed decode for free. This is the
   "battery-included" ergonomic that bgp-rs/zettabgp lack.
3. **Run `cargo-semver-checks` in CI** against the published wire crate so
   accidental breaking changes are caught before publish. Add to
   `.github/workflows/ci.yml` on the wire crate path.
4. **docs.rs is the storefront.** Ensure `cargo doc` is warning-clean (already
   a release gate) and that the README's supported-RFC table stays the landing
   page. Add per-type examples in doc-comments for `decode_message`,
   `encode_message`, `UpdateMessage::parse`, `UpdateMessage::try_build`.
5. **Be honest about what the codec is *not*.** It is not a session runtime,
   not a RIB, not a router. The embedder that needs a full in-process router
   (Cilium) cannot get it from rustbgpd as a library today. The embedder that
   needs a *codec* or a *pure FSM* — monitors, analyzers, test harnesses,
   minimal speakers, RPKI validators — can, and in Rust, with memory safety and
   no CGo. That is the wedge.

---

## 7. Published-crate release boundary

`rustbgpd-wire 0.17.0` and `rustbgpd-fsm 0.3.1` are published and are the
versions the §3 dependency examples name. The ordering rules that govern every
future publish are:

- Publish `rustbgpd-wire` first, then verify it is registry-visible. Only then
  run the fully verified package/dry-run gate for `rustbgpd-fsm`. Cargo
  normalizes the FSM's path dependency to a caret requirement on the wire
  version, so a full FSM package verify cannot resolve before that wire release
  is present in the registry.
- Keep the dependency examples in §3 pinned to the versions actually available
  from crates.io — never to a version not yet published.
- Both crates keep their package metadata and README; the README is the rendered
  docs.rs landing page and carries the per-version compatibility notes.
- Treat any additional crate publish as separate, demand-gated work.

`docs/RELEASE_CHECKLIST.md` holds the executable form of this, including the
per-crate semver bump rules.

---

## 8. The Shape-A (gRPC) embedder surface — recent additions

Shape A (§3.4) — a separate process driving the daemon over gRPC — is
the recommended production embedding, and its surface grew. What a
gRPC consumer gains from the recent proto additions
(`proto/rustbgpd.proto`; all additive):

- **`Route.received_at_epoch_seconds`** — every `Route` served by
  `ListReceivedRoutes` / `ListBestRoutes` / `ListAdvertisedRoutes`
  (and the explain RPCs that embed `Route`) now carries its receive
  time, recovered from the monotonic RIB receive instant. Consumers
  no longer need to track route age themselves by diffing streams.
  Approximation: the recovery reads the wall clock and the monotonic
  elapsed separately, so a wall-clock step between the two reads skews
  the reported epoch by that step. It is a display timestamp, not a
  precise event ordering key — use the monotonic `event_id` for that.
- **`RibService.ExplainAdvertisedRoute`** — the export decision as
  data: the full gate ladder (`split_horizon`, `rr_reflection`,
  `family`, `llgr`, `orf`, `rt_membership`, `export_policy`,
  `adj_rib_out`) with per-gate verdict + detail, produced by a dry
  run of the same staging body live distribution executes. A
  controller can answer "why isn't prefix X on peer Y" without
  screen-scraping. The response's `update_group_id` and
  `NeighborState.update_group` expose ADR-0098 group membership for
  fleet-level diagnostics.
- **Live update-group comparison** — set
  `GetNeighborStateRequest.compare_address` (plus the matching
  `compare_interface` identity field when present) to compare two configured
  peers.
  The response's optional `NeighborState.update_group_comparison` carries an
  ID-free `shared`, `separate`, `private`, or `unknown` verdict, each side's
  membership (`grouped`, `unknown`, or a private-path reason), and the stable
  semantic differences between two separate groups: export policy, session
  kind, RR-client role, local BGP role, RFC 1997 mode, negotiated families, and
  LLGR families. `private` means at least one side uses a per-peer fallback;
  inspect the two membership fields for the reason. `unknown` means at least
  one configured peer has no live outbound registration or its group metadata
  is unavailable. Process-local values such as `NeighborState.update_group =
  "group:N"` remain diagnostic only and must not be persisted as identifiers.

  The primary peer still uses `GetNeighborStateRequest.address` plus
  `interface`. Both peers must exist. IPv6 global addresses are supported, but
  the daemon currently rejects a comparison involving an IPv6 link-local peer,
  even when the usual `fe80::1` + `interface = "eth0"` scoped form is supplied.
  The compare request/response fields were added to the existing proto, so an
  older daemon ignores the unknown request fields and returns no
  `update_group_comparison`; treat absence after a compare request as "feature
  unsupported", not as `shared` and not as permission to compare `group:N`
  strings. The in-tree `rbgp` client reports this case as
  `update-group comparison is not supported by this daemon`.
- **RFC 8212 directional policy status (ADR-0112)** —
  `NeighborState.rfc8212_import_policy` and `.rfc8212_export_policy` carry
  `Rfc8212PolicyStatus` per direction: `NOT_REQUIRED` (enforcement off, or
  iBGP), `PRESENT`, or `MISSING` (the reserved internal deny is installed and
  no route crosses that direction). A daemon that predates the fields leaves
  them at `UNSPECIFIED = 0`; treat that and any unrecognized future value as
  "unknown", never as `NOT_REQUIRED`, or a rolling upgrade will report a peer
  as unconstrained while its deny is live. Do not collapse the two into one
  boolean — a peer with an import policy and no export policy is a real state.
- **`send_hold_time` (RFC 9687)** — settable in `AddNeighbor`'s
  `NeighborConfig` and in `PeerGroupDefinition`, with the same
  validation as the config path; `ListNeighbors` reports the
  effective value. Automation that provisions peers can now manage
  the wedged-peer teardown timer instead of inheriting the default.
- **`max_prefix_restart_seconds`** — settable in `AddNeighbor`'s
  `NeighborConfig` and in `PeerGroupDefinition`; zero is rejected on both
  surfaces. Omit it to retain the fail-closed max-prefix shutdown until an
  explicit enable.

**The event-replay contract** (`EventService.SubscribeFromEvent`,
ADR-0072) is the durable half of the event surface and the one an
integration should build on: events carry a monotonic `event_id`;
the consumer persists the last id it processed and resumes with
`from_event_id` after either side restarts. It requires
`[event_history].enabled = true` on the daemon and returns
`FAILED_PRECONDITION` otherwise — treat that as "replay not
provisioned", not an error to retry. The live `WatchEvents` stream
emits `stream_lagged` warnings when a bounded source dropped events;
that is the signal to fall back to the durable cursor.

**Reference consumers in-tree:** `examples/event-bridge/` (gRPC →
JSON-lines event bridge, the minimal Shape-A skeleton) and
`examples/birdwatcher-adapter/` (a Birdwatcher-shaped status, peer,
accepted-route, filtered-route, and noexport REST subset sourced entirely
from the public gRPC API, including per-route `age` from
`received_at_epoch_seconds`, `GET /routes/filtered/{id}` served from
`PolicyService.ListRejectedRoutes` with structured reject reasons, and
`GET /routes/noexport/{id}` served from the `ListBestRoutes` −
`ListAdvertisedRoutes` diff with each suppression explained by
`RibService.ExplainAdvertisedRoute`). Both live in this workspace, so they take
`rustbgpd-api` as a path dependency; read them for the call shapes and the RPC
sequencing, but generate your own client from the proto (§3.4) rather than
copying that dependency line. The adapter is the honest template: if the public
API is missing a field an external tool needs, the fix is an additive proto
field, not a daemon-internal shortcut — that is how `received_at_epoch_seconds`
landed.

**Stability posture:** the daemon is alpha and the proto is versioned
by convention, not frozen — but the working convention is additive
evolution (new fields and RPCs; `optional` scalars for new knobs),
with any breaking change called out in `CHANGELOG.md`. Generated
client code should tolerate unknown fields (protobuf's default) and
gate features on field presence, not daemon version.
