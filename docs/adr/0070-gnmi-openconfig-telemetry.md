# ADR-0070: Read-only gNMI / OpenConfig telemetry adapter

**Status:** Accepted
**Date:** 2026-05-25

## Context

Cloud and whitebox operators already aggregate device state through
gNMI / OpenConfig tooling (`gnmic`, `gnmi-gateway`, OpenConfig collectors).
Before ADR-0070 landed, rustbgpd exposed rich typed gRPC snapshots and event
streams, but only through its own `rustbgpd.v1` proto — there was no
OpenConfig-modelled, gNMI-spoken surface, so it could not drop into an existing
OpenConfig telemetry pipeline. Closing that gap was the highest-leverage
remaining adoption item once BGP unnumbered, BFD, and ECMP had shipped.

It is also a clean differentiator. **GoBGP** has a rich native gRPC API and
Prometheus metrics but does **not** speak OpenConfig/gNMI. **FRR** can carry
OpenConfig models, but only through `mgmtd` / SONiC-style management frameworks
layered on top — its per-daemon (`bgpd`) gNMI story is experimental and uneven,
and the upstream `mgmtd` northbound currently fronts CLI with RESTCONF/NETCONF
as future work. A *native*, read-only OpenConfig BGP gNMI target inside the BGP
daemon itself is therefore a genuine edge for the route-reflector / SDN / data
center-fabric use case.

gNMI itself constrains the design (spec v0.10.0):

- The service is always four RPCs — `Capabilities`, `Get`, `Set`, `Subscribe`.
  Even a read-only server must answer `Set` explicitly; it is not optional.
- `Capabilities` is the discovery point: `CapabilityResponse` returns the
  `gNMI_version`, the `supported_models`, and the `supported_encodings`. It is
  not a hidden debug endpoint — collectors negotiate against it, so the
  advertised models/encodings/version must be accurate.
- JSON is the default encoding when the client omits one; the registered set is
  `JSON, BYTES, PROTO, ASCII, JSON_IETF`.
- `Subscribe` modes are `ONCE`, `POLL`, and `STREAM`; `STREAM` sub-modes are
  `SAMPLE`, `ON_CHANGE`, and `TARGET_DEFINED`.
- The spec mandates transport security: the session **MUST** be TLS and a
  target **MUST NOT** fall back to unencrypted sessions.

Two existing rustbgpd facts shape what we can honestly ship:

- **Authorization already exists** (ADR-0064): a totally-ordered tier model
  `Read < SensitiveRead < Mutating < OperatorOnly`, enforced by a Tower layer
  over every listener plus a static per-method matrix. Read-only telemetry that
  discloses topology/RIB/neighbor state maps cleanly onto the existing
  `SensitiveRead` tier.
- **Typed snapshots are already plumbed** through `ServeConfig` (RIB query
  channel, peer-manager command channel, FIB / BFD / EVPN snapshot closures), so
  a read-only service can consume them without new channels. But the event
  streams are bounded and lossy, and several OpenConfig leaves are not currently
  sourceable per-family (see "What v1 does not expose").

## Decision

Build a **read-only gNMI target inside rustbgpd**, backed by the existing typed
snapshots and services. It is **not** a config datastore, **not** a general YANG
engine, and **not** a CLI-scraper — every value is rendered from a typed
internal snapshot, never from CLI text.

### Service surface (v1)

| RPC | v1 behaviour |
|-----|--------------|
| `Capabilities` | Advertise gNMI version `0.10.0`, the **OpenConfig modules** (name / organization / version, via `ModelData`) backing the supported paths, and encodings `JSON` + `JSON_IETF`. `ModelData` is module-level, not per-path — the path subset is enforced at `Get` / `Subscribe`, not advertised here. |
| `Get` | OpenConfig BGP operational-state subset (below). |
| `Subscribe` | `ONCE`, `POLL`, and `STREAM` with `SAMPLE`. `ON_CHANGE` deferred. |
| `Set` | Always returns a stable `Unimplemented` status. gNMI requires an explicit answer; rustbgpd has no config-transaction model, so mutation stays closed. |

### OpenConfig path scope — a supported *subset*, not full OpenConfig BGP

All paths hang off the standard network-instance mount of `openconfig-bgp`:

```
/network-instances/network-instance[name=DEFAULT]
  /protocols/protocol[identifier=BGP][name=BGP]/bgp/...
```

Key conventions: the default network instance uses the OpenConfig name `DEFAULT`
(the model's default-instance name); the BGP protocol `identifier` is the `BGP`
identity (gNMI path keys use the bare identity value, not the YANG-qualified
`oc-pol-types:BGP`) and `name` is the operator-assigned instance name (commonly
`BGP`). The target keys by the configured protocol name and may accept lowercase
`default` / a module-qualified `identifier` as aliases. OpenConfig keys neighbors
by **bare IP** `neighbor-address` (not a `fe80::x%ifname` zone string); v1
deliberately keys scoped IPv6 link-local peers by their bare address, which is
safe because config forbids the same link-local address on more than one
interface (ADR-0069).

v1 supports exactly these leaves (each is backed by a verified internal source):

- **Global** — `bgp/global/state/`:
  - `as`, `router-id` (static config via `GlobalService`).
  - `total-prefixes` / `total-paths` are **deferred**: OpenConfig defines
    `total-prefixes` as BGP prefixes *received* in context, which the available
    Loc-RIB best-path count (`RibUpdate::QueryLocRibCount`) does not represent,
    and there is no pre-best-path total-paths aggregate — faking either would
    misstate the counter.
- **Neighbors** — `bgp/neighbors/neighbor[neighbor-address=X]/state/`:
  - `neighbor-address`, `enabled`, `peer-as`, `local-as`, `session-state`
    (the FSM maps 1:1 onto OpenConfig's six states), `established-transitions`
    (the flap counter), and `messages` UPDATE / NOTIFICATION in/out counters.
  - `last-established` is **deferred**: OpenConfig defines it as the absolute
    timestamp of the last transition *into or out of* Established, but the peer
    snapshot tracks only elapsed-since-Established (correct only while currently
    Established, and it loses the out-of-Established case). It needs a real
    last-transition timestamp on the peer snapshot first.

The path set is a **strict whitelist enforced at `Get` / `Subscribe`** — a valid
OpenConfig model path outside the whitelist returns `UNIMPLEMENTED`.
`Capabilities` advertises the OpenConfig *modules* backing these paths
(`ModelData` is module-level, not per-path), so the whitelist is the runtime
contract, not a capability-level claim.

### What v1 does **not** expose (and why)

These are declared unsupported up front rather than rendered from weak data:

- **Per-AFI-SAFI prefix counters** (`afi-safis/afi-safi[...]/state/prefixes/
  {received,sent,installed}`). The only per-neighbor prefix count today is an
  aggregate across unicast + FlowSpec + EVPN, not split per family. Exposing it
  under a per-AFI path would misrepresent the data.
- **Per-neighbor `installed` / `accepted` split.** Only a single global Loc-RIB
  best-path count exists; there is no trustworthy per-neighbor installed-best
  count. The aggregate per-neighbor counter conflates received-and-accepted.
- **`supported-capabilities` and negotiated AFI-SAFI lists.** Negotiated state
  lives inside the session but is not surfaced through the peer snapshot, so
  these leaves wait on a snapshot extension.

### Encoding

Support `JSON` (the spec default) and `JSON_IETF`. Documentation and examples
use `JSON_IETF` because OpenConfig tooling expects it; `JSON` remains because
the spec makes it the fallback when a client omits the encoding.

### Subscribe semantics

- `ONCE` — render the snapshot, stream the updates, send `sync_response=true`,
  close.
- `POLL` — keep the stream open; each poll emits a fresh snapshot then `sync`.
- `STREAM` `SAMPLE` — periodic snapshots for the subscribed paths, behind a
  minimum sample-interval floor.
- `ON_CHANGE` is **deferred**: today's broadcast event streams are bounded and
  lossy and are not path-diffed into per-leaf OpenConfig updates, and true
  `ON_CHANGE` needs careful initial-snapshot, delete, and backpressure
  semantics. It depends on the P1 durable-event-history work.

Wildcard / subtree `Get` and `Subscribe` requests are bounded so a broad path
cannot turn into an accidental full route-table dump (v1 does not stream the RIB).

### Security model

gNMI mandates TLS with no plaintext fallback, which folds into the existing
listener model rather than adding a new one:

- gNMI is served **only** on a TCP listener that has mTLS configured
  (`tls.is_some()`) — registration is gated on the listener's TLS config, and a
  plaintext or token-only TCP listener never carries gNMI — matching the spec's
  TLS-MUST / no-plaintext-fallback rule. The UDS listener may also serve gNMI as
  a **local-only extension** for a co-located collector; this is a deliberate
  convenience, *not* standards-compliant network gNMI (which requires TLS).
  **Non-local deployments must use the mTLS TCP listener, never plaintext TCP.**
- `Get`, `Subscribe`, and `Capabilities` are classified at the **`SensitiveRead`**
  tier (ADR-0064) — identical to `GetGlobal` / `ListNeighbors` / the RIB reads,
  because they disclose topology, neighbor, and routing state. They are governed
  automatically by the per-listener `max_tier` cap and per-principal role
  enforcement once their method paths are added to the authz matrix.
- `Set` is closed (`Unimplemented`) but still classified as **`OperatorOnly`**
  in the authz matrix because it is mutation-shaped and must remain future-safe.
  A future implemented `Set` would stay `Mutating` / `OperatorOnly` and be gated
  on a daemon-wide config-transaction model.

> **Load-bearing wiring note.** Authorization fails closed: any method path not
> present in the static authz matrix is treated as `OperatorOnly` and denied. The
> matrix self-test asserts it mirrors `proto/rustbgpd.proto` exactly. gNMI lives
> in its own proto package, so its methods **must** be added to the authz matrix
> and `docs/grpc-method-inventory.json` (and the matrix-count test updated) or
> the gNMI RPCs are unreachable by construction.

## Slicing

| PR | Scope | Verification |
|----|-------|--------------|
| **PR1** | Vendor `gnmi.proto` (+ `gnmi_ext.proto`), wire codegen, add `GnmiService`; implement `Capabilities`; `Get`/`Subscribe` return `Unimplemented`; `Set` returns a stable `Unimplemented`. Register on the UDS listener and on the TCP listener **only when mTLS is configured** (both `.add_service` chains in `server.rs`). Add the gNMI methods to the ADR-0064 authz matrix + `grpc-method-inventory.json` (`Capabilities` / `Get` / `Subscribe` as `SensitiveRead`, `Set` as `OperatorOnly`) and fix the count tests. | `gnmic capabilities` returns version `0.10.0`, the advertised model subset, and `JSON`/`JSON_IETF`. |
| **PR2** | `Get` for the OpenConfig BGP global + neighbor subset above. Structured `PathElem` parser (not legacy string elements), strict supported-path whitelist. Error mapping: `INVALID_ARGUMENT` for malformed paths, `UNIMPLEMENTED` for valid-but-unsupported OpenConfig paths, `NOT_FOUND` for valid-but-absent keyed objects. | `gnmic get` against global + a keyed neighbor renders correct JSON_IETF. |
| **PR3** | `Subscribe` `ONCE` / `POLL` / `STREAM SAMPLE` reusing the PR2 snapshot renderer; stream limits + sample-interval floors; no full route-table dumps. | `gnmic subscribe --mode once`, `--mode poll`, and stream/sample against the subset. |
| **PR4** (post-v1) | Per-AFI-SAFI counters once per-family counts are plumbed; `supported-capabilities` once the peer snapshot is extended; BFD / FIB / EVPN OpenConfig-adjacent (or native-origin) telemetry. | — |

## Implementation status

User-facing setup, supported-path, `gnmic`, and troubleshooting guidance lives in
[docs/GNMI.md](../GNMI.md). This ADR records the design boundary and rationale.

| Slice | Status |
|-------|--------|
| PR1 — proto + codegen + `Capabilities` + `Set`-closed | Landed (PR #275) |
| PR2 — `Get` OpenConfig BGP global + neighbors | Landed (PR #276) |
| PR3 — `Subscribe` ONCE / POLL / SAMPLE | Landed (PR #277) |
| M54 — hosted `gnmic` smoke over native mTLS | Landed: `Capabilities`, `Get`, and `Subscribe STREAM/SAMPLE` are exercised by a real OpenConfig collector client |
| PR4 — counters / capabilities / non-BGP telemetry | Deferred |

## Repo seams

Grounded against the current checkout:

- **Codegen:** `crates/api/build.rs` compiles both the native `rustbgpd.v1`
  proto and the vendored OpenConfig gNMI protos
  (`proto/github.com/openconfig/gnmi/proto/gnmi/{gnmi,gnmi_ext}.proto`);
  `crates/api/src/lib.rs` exposes `pub mod gnmi` and `pub mod gnmi_ext`.
- **Service registration:** `crates/api/src/server.rs` registers `gnmi.gNMI` on
  the UDS listener and on TCP listeners only when mTLS is configured, behind the
  existing `GrpcAuthzLayer`.
- **Authorization:** `crates/api/src/authz.rs` (the `METHODS` matrix + tier enum),
  `crates/api/src/authz_runtime/layer.rs` (runtime enforcement, fail-closed),
  `docs/grpc-method-inventory.json`. See ADR-0064.
- **Global state:** `crates/api/src/global_service.rs` (ASN / router-id /
  listen-port). The only aggregate count is `crates/api/src/control_service.rs`
  `get_health` → `RibUpdate::QueryLocRibCount` (Loc-RIB best-path count);
  `total-prefixes` / `total-paths` are deferred (see Deferred).
- **Neighbor state:** `src/peer_manager/snapshot.rs` (`build_peer_info`),
  `crates/api/src/peer_types.rs` (`PeerInfo`, `PeerManagerCommand::ListPeers`),
  `crates/api/src/neighbor_service.rs` (`peer_info_to_proto`).
- **Snapshot/provider closures:** `ServeConfig` in `crates/api/src/server.rs`
  (RIB query channel, peer-manager channel, FIB / BFD / EVPN snapshots) — a
  read-only gNMI service consumes these directly; no new channels.

## Consequences

- rustbgpd becomes a drop-in read-only OpenConfig BGP target for `gnmic` /
  `gnmi-gateway` / OpenConfig collector pipelines — a differentiator over GoBGP
  (gRPC-only) and FRR-`bgpd` (no native per-daemon gNMI).
- It is strictly read-only and reuses existing snapshots, so it adds no config
  risk and no new RIB/peer ownership or channels.
- `Capabilities` must advertise an honest, narrow subset; over-claiming models,
  encodings, or paths breaks collectors, so the whitelist and the deferral list
  are part of the contract, not an afterthought.
- The main implementation cost is the OpenConfig `PathElem` parser + the
  snapshot→OpenConfig-leaf renderer; the per-AFI / capability data plumbing is
  deliberately deferred rather than faked.
- This work pulls on two adjacent roadmap items: P1 durable event history
  (the prerequisite for honest `ON_CHANGE`) and P2 config transaction model
  (the prerequisite for any future `Set`).

## Deferred

- **gNMI `Set` / config datastore** — needs the ADR-0064-gated config
  transaction model (roadmap P2). v1 `Set` returns `Unimplemented`.
- **`Subscribe ON_CHANGE`** — needs loss-free, path-diffed leaf events.
  **Unblocked by [ADR-0072](0072-durable-event-history.md);** ships
  once the durable outbox lands and provides restart-survivable change
  cursors.
- **Per-AFI-SAFI prefix counters** (`received` / `sent` / `installed`) — no
  trustworthy per-family source today.
- **Per-neighbor `installed` / `accepted` prefix split** — only a global Loc-RIB
  best-path count exists.
- **`supported-capabilities` / negotiated AFI-SAFI state** — needs a peer
  snapshot extension to surface negotiated capabilities.
- **`global/state/total-prefixes` and `total-paths`** — `total-prefixes` means
  prefixes *received* in context, which the Loc-RIB best-path count we have does
  not represent; `total-paths` has no pre-best-path aggregate.
- **`neighbors/neighbor[...]/state/last-established`** — needs an absolute
  last-transition (into/out of Established) timestamp on the peer snapshot; only
  elapsed-since-Established is tracked today.
- **`PROTO` / `ASCII` encodings**, multicast / VPN AFIs, and full OpenConfig BGP
  model coverage.
- **BFD / FIB / EVPN OpenConfig(-adjacent) telemetry** — after the BGP subset
  proves the path-parser + renderer pattern.
- **YANG / NETCONF / RESTCONF** — separate and deprioritized; gNMI is the
  telemetry-first, gRPC-native surface.

## References

- gNMI specification (v0.10.0), OpenConfig:
  <https://openconfig.net/docs/gnmi/gnmi-specification/>
- gNMI authentication and encryption guidance:
  <https://www.openconfig.net/docs/gnmi/gnmi-authentication/>
- OpenConfig BGP model (`openconfig-bgp`):
  <https://openconfig.net/projects/models/schemadocs/yangdoc/openconfig-bgp.html>
- `gnmic` (OpenConfig gNMI client):
  <https://gnmic.openconfig.net/>
- ADR-0064 — gRPC tier authorization (the `SensitiveRead` tier + enforcement).
- ADR-0037 — gRPC API foundation.
- `ROADMAP.md` — P0 (this adapter), P1 (durable event history → `ON_CHANGE`),
  P2 (config transaction model → future `Set`).
