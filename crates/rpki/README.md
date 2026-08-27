# rustbgpd-rpki

RPKI origin validation, ASPA path verification, an RTR protocol client, and
multi-cache table management for Rust applications.

Part of [rustbgpd](https://github.com/lance0/rustbgpd). Requires Rust 1.95 or
newer. Release-by-release crate changes are recorded in the
[changelog](CHANGELOG.md).

## What this crate provides

- **VRP table** — a synchronous, immutable `VrpTable` for RFC 6811 origin
  validation.
- **RTR client** — an asynchronous client that prefers the ASPA-capable
  protocol v2 shape and falls back to RFC 8210 version 1 when the cache
  explicitly rejects v2. `RtrClientConfig::max_expire_interval` adds an
  optional operator freshness ceiling: it clamps both the configured
  `expire_interval` and a cache-advertised End of Data expire down, never raises
  a lower value, and when unset leaves the configured interval unchanged while
  cache-advertised values retain the protocol ceiling. The crate exports the
  RFC 8210 two-day ceiling as `RTR_EXPIRE_MAX_SECS` (`172800` seconds).
- **ASPA path verification** — a synchronous `AspaTable` plus role-aware path
  verification.
- **Multi-cache merge** — a `VrpManager` that merges retained contributions
  from multiple RTR caches and publishes immutable VRP and ASPA snapshots.

The standalone crate does not select BGP best paths or evaluate rustbgpd policy
statements. In the daemon, `rustbgpd-rib` consumes these validation results in
best-path selection and `rustbgpd-policy` exposes validation match conditions;
those are workspace integrations, not capabilities supplied by this package.

The crate's direct dependency set is `rustbgpd-wire`, `smallvec`, `thiserror`,
`tokio`, `tracing`, and `rustc-hash`. Table construction and validation are
synchronous. `RtrClient` and `VrpManager` require a Tokio runtime.

## Usage

Origin validation uses prefix and validation-state types from the independently
published wire crate:

```toml
[dependencies]
rustbgpd-rpki = "0.1.0"
rustbgpd-wire = "0.18.0"
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
| `draft-ietf-sidrops-aspa-verification-27` | Role-aware upstream/downstream ASPA path verification for IPv4 and IPv6 unicast. |

RTR cache connections use plain TCP. TLS and SSH transports are not implemented.
Transactions are bounded by time, record count, and byte count; validated data
is retained across reconnects until replacement or expiry.

## Public API boundary

The crate-root facade exports the primary application surface:

- `VrpEntry`, `VrpTable`, `AspaRecord`, and `AspaTable`
- `AspaInvalidHop`, `AspaVerificationResult`, and `ValidationSnapshot`
- `RtrClient`, `RtrClientConfig`, `VrpUpdate`, and `RTR_EXPIRE_MAX_SECS`
- `VrpManager`, `RpkiTableUpdate`, and `AspaTableUpdate`

The public modules are also part of the `0.1.x` API. They expose the advanced
ASPA helpers (`ProviderAuth`, `verify`, `verify_detailed`, `verify_upstream`),
the raw RTR PDU codec (`RtrPdu`, its version constants, `RtrDecodeError`, and
`RtrEncodeError`), the client-side `RtrError`, and the module-qualified forms
of the facade types. Publishing `0.1.0` freezes all of those public paths for
the `0.1.x` compatibility line; they are not merely internal implementation
details.

## Compatibility

This is an alpha `0.x` crate. Backward-compatible fixes and additions remain on
the `0.1.x` line. Removing or changing public items requires `0.2.0`. Public
method signatures use types from `rustbgpd-wire 0.18`; moving that dependency
to an incompatible wire line also requires an RPKI minor-version bump so the
shared types do not silently split in one dependency graph.

## License

MIT OR Apache-2.0
