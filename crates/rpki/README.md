# rustbgpd-rpki

RPKI origin validation, ASPA path verification, an RTR protocol client, and
multi-cache table management for Rust applications.

Part of [rustbgpd](https://github.com/lance0/rustbgpd). Requires Rust 1.95 or
newer. Release-by-release crate changes are recorded in the
[changelog](CHANGELOG.md).

The source checkout prepares the `0.3.0` compatibility line with wire `0.21.0`.
Upgrade dependencies that exchange public wire types together. This release also
makes four RTR enums non-exhaustive; downstream exhaustive matches need a
fallback, as described under [Enum exhaustiveness](#enum-exhaustiveness).
These compatibility changes do not alter runtime behavior.

## What this crate provides

- **VRP table** — a synchronous, immutable `VrpTable` for RFC 6811 origin
  validation plus a deterministic, 256-row-bounded covering-VRP diagnostic.
- **RTR client** — an asynchronous client that prefers the ASPA-capable
  protocol v2 shape and falls back to RFC 8210 version 1 when the cache
  explicitly rejects v2. Version 2 rejects IPv4 and IPv6 Prefix PDUs with
  nonzero host bits as corrupt data; RFC 8210 v1 continues to accept those
  host bits. Invalid prefix-length and max-length PDUs on either version share
  the same fatal code-0 flush disposition as other corrupt Prefix PDUs.
  `RtrClientConfig::max_expire_interval` adds an
  optional operator freshness ceiling: it clamps both the configured
  `expire_interval` and a cache-advertised End of Data expire down, never raises
  a lower value, and when unset leaves the configured interval unchanged while
  cache-advertised values retain the protocol ceiling. The crate exports the
  RFC 8210 two-day ceiling as `RTR_EXPIRE_MAX_SECS` (`172800` seconds).
- **ASPA path verification** — a synchronous `AspaTable` plus role-aware path
  verification.
- **Multi-cache merge** — a `VrpManager` that merges retained contributions
  from multiple RTR caches and publishes immutable VRP and ASPA snapshots. An
  optional `CacheInventoryAttachment` supplies distinct enhanced-update and
  bounded query handles without changing the legacy constructors or
  `VrpUpdate` contract.

The standalone crate does not select BGP best paths or evaluate rustbgpd policy
statements. In the daemon, `rustbgpd-rib` consumes these validation results in
best-path selection and `rustbgpd-policy` exposes validation match conditions;
those are workspace integrations, not capabilities supplied by this package.

The crate's direct dependency set is `rustbgpd-wire`, `smallvec`, `thiserror`,
`tokio`, `tracing`, and `rustc-hash`. Table construction and validation are
synchronous. `RtrClient` and `VrpManager` require a Tokio runtime.

## Usage

Origin validation uses prefix and validation-state types from the independently
published wire crate. These registry examples use the repository's verified
published versions:

```toml
[dependencies]
rustbgpd-rpki = "0.2.0"
rustbgpd-wire = "0.20.0"
```

When building against a source checkout instead, use matching versioned paths
from one rustbgpd checkout:

```toml
[dependencies]
rustbgpd-rpki = { version = "0.3.0", path = "../rustbgpd/crates/rpki" }
rustbgpd-wire = { version = "0.21.0", path = "../rustbgpd/crates/wire" }
```

```rust
use std::net::{IpAddr, Ipv4Addr};

use rustbgpd_rpki::{VrpEntry, VrpTable};
use rustbgpd_wire::{Ipv4Prefix, Prefix, RpkiValidation};

let table = VrpTable::new(vec![VrpEntry {
    prefix: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)),
    prefix_len: 24,
    max_len: 24,
    origin_asn: 64_496,
}]);
let route = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24));

assert_eq!(table.validate(&route, 64_496), RpkiValidation::Valid);

let covering = table.covering_vrps(&route, 64_496, 256);
assert!(covering.rows[0].authorizes);
assert_eq!(covering.omitted, 0);
```

The same public-API walkthrough is kept compiling as an in-tree example:

```sh
cargo run -p rustbgpd-rpki --example origin_validation
```

Applications that run `RtrClient` or `VrpManager` also need Tokio features for
their chosen runtime and for `tokio::sync::mpsc`. The client owns no runtime; it
runs inside the task the application supplies.

## Protocol support

| Specification | Implemented scope |
|---|---|
| RFC 1982 | Serial-number ordering for incremental RTR epochs. |
| RFC 6482 | Validated ROA Payload prefix, maximum-length, and origin-AS semantics. |
| RFC 6811 | `Valid`, `Invalid`, and `NotFound` origin validation over every covering VRP. |
| RFC 8210 | RTR version 1 client and PDU codec, including serial/reset synchronization and expiry. |
| `draft-ietf-sidrops-8210bis` | Scoped RTR version 2 support for ASPA records, with v1 fallback. Router Key PDUs are not implemented. |
| `draft-ietf-sidrops-aspa-verification-28` | Role-aware upstream/downstream ASPA path verification for IPv4 and IPv6 unicast. |

RTR cache connections use plain TCP by default; an embedding daemon can open them
through its own dialer (`RtrClient::with_dialer`) to install TCP MD5 or TCP-AO
before connect. TLS and SSH transports are not implemented.
Transactions are bounded by time, record count, and byte count; validated data
is retained across reconnects until replacement or expiry.

## Public API boundary

The crate-root facade exports the primary application surface:

- `VrpEntry`, `VrpTable`, `CoveringVrp`, `CoveringVrps`,
  `MAX_COVERING_VRPS`, `AspaRecord`, and `AspaTable`
- `AspaInvalidHop`, `AspaVerificationResult`, and `ValidationSnapshot`
- `RtrClient`, `RtrClientConfig`, `VrpUpdate`, and `RTR_EXPIRE_MAX_SECS`
- `CacheInventoryAttachment`, `CacheUpdateHandle`, and `CacheQueryHandle` for
  atomic accepted-epoch inventory when the optional attachment is used
- `VrpManager`, `RpkiTableUpdate`, and `AspaTableUpdate`

The public modules are also part of the public API. They expose the advanced
ASPA helpers (`ProviderAuth`, `verify`, `verify_detailed`, `verify_upstream`),
the raw RTR PDU codec (`RtrPdu`, its version constants, `RtrDecodeError`, and
`RtrEncodeError`), the client-side `RtrError`, and the module-qualified forms
of the facade types. Publishing `0.1.0` froze all of those public paths for
the `0.1.x` compatibility line; they are not merely internal implementation
details.

## Compatibility

This is an alpha `0.x` crate. Backward-compatible fixes and additions use patch
releases within a compatibility line. Breaking public API changes or an
incompatible public wire-type dependency require the next `0.x` minor version.
The first `0.1.x` line used wire `0.19`; published `0.2.x` uses wire `0.20`.
The prepared `0.3.x` line uses wire `0.21` and adopts the enum policy below.

## Enum exhaustiveness

Starting with `0.3.0`, these public enums have explicit evolution contracts:

| Enum | Policy | Reason |
|---|---|---|
| `rtr_codec::RtrPdu` | `#[non_exhaustive]` | The protocol PDU set can grow. |
| `rtr_codec::RtrDecodeError` | `#[non_exhaustive]` | Decoding diagnostics can grow. |
| `rtr_codec::RtrEncodeError` | `#[non_exhaustive]` | Encoding diagnostics can grow. |
| `rtr_client::RtrError` | `#[non_exhaustive]` | Client failure diagnostics can grow. |
| `aspa::ProviderAuth` | Exhaustive | A lookup finds a provider, finds a non-provider, or lacks an attestation. |
| `VrpUpdate` | Exhaustive | The legacy full-table, incremental-update, and server-down contract stays closed. |

The four attributes are on enums, not their variants. Existing unit, tuple,
and struct variants remain directly constructible, with the same field access.
Downstream matches must include a fallback for future variants. For example:

```rust
use rustbgpd_rpki::rtr_codec::RtrDecodeError;

fn needs_more_bytes(error: &RtrDecodeError) -> bool {
    match error {
        RtrDecodeError::Incomplete => true,
        _ => false,
    }
}
```

Treat an unfamiliar error as an error, and give unfamiliar PDUs an explicit
unsupported-case policy in a custom protocol consumer. A wildcard is not a
reason to treat unknown data as valid. This release adds no variants and does
not change decoding, encoding, or client error handling; Router Key PDUs remain
unsupported.

Adding these attributes breaks exhaustive matches accepted by `0.2.x`, including
irrefutable destructuring of the single `RtrEncodeError` variant. The change is
part of the `0.3.0` compatibility boundary. Future variants of these four enums
can be added in a `0.3.x` patch release; changing existing variant fields still
requires a breaking release. Adding variants to `ProviderAuth` or `VrpUpdate`
also remains a breaking change. The optional cache-inventory attachment does
not change the legacy `VrpUpdate` contract.

## License

MIT OR Apache-2.0
