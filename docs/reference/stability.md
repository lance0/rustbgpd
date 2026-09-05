# Stability and compatibility

> **Document class: REFERENCE.** This maintained page defines a contract, specification, or reusable procedure; follow any stated version scope.

rustbgpd remains **public alpha overall**. Features can be shipped, tested, or
assigned an authorization tier without becoming compatibility promises.

This page is navigation, not another inventory. When wording here and a linked
contract differ, use the linked contract.

## Narrow stable daemon surface

The only stable daemon boundary is the exact inventory in
[`v1-stable-surface.json`](v1-stable-surface.json). It applies to the listed
surfaces for the `route-server-unicast` and `route-reflector-unicast` roles;
absence from that inventory means absence from the v1 promise.

Read the inventory with the
[v1 route-server / route-reflector contract](v1-stable-contract.md), which
defines compatible evolution, migration support, and the evidence required for
a breaking change. Do not infer stability for a containing config object,
protobuf service, CLI subtree, JSON object, or feature from one inventoried
member.

In particular:

- EVPN, including EVPN route-reflector use, remains alpha.
- Linux dataplane work, including FIB and managed-netdev behavior, remains
  outside the control-plane contract.
- Experimental features remain outside the contract.
- Unlisted RPCs and CLI commands remain alpha. For an inventoried CLI command,
  only the dimensions named by the inventory are stable; flags and output are
  not stable by implication.

For operational boundaries and non-goals, see
[`LIMITATIONS.md`](limitations.md).

## Authorization is a different classification

The [gRPC method inventory](grpc-method-inventory.md) assigns every method an
authorization tier. A tier answers who may call a method and which listener may
serve it; it does **not** classify compatibility. Check
[`v1-stable-surface.json`](v1-stable-surface.json) separately before treating
an RPC signature or behavior as stable.

## Embedding and crate versions

Published Rust crates follow their own SemVer boundary, independently of the
daemon's narrow v1 contract. Use the versions and upgrade guidance in
[`EMBEDDING.md`](embedding.md#7-published-crate-release-boundary), including the
per-release compatibility notes and coordinated dependency guidance. A daemon
release or an inventoried daemon surface does not make an internal workspace
crate a supported library API.

## Bird's Eye adapter compatibility

`birdwatcher-adapter` has a separate, bounded compatibility contract. The claim
is verified IXP Manager 7.4 Bird's Eye API compatibility with documented
BIRD-internal divergences, for the pinned consumer surface and allow-list in
the [executable contract](../../tests/compat/ixp-manager-birdseye/contract.json).
It is not a claim of unqualified Bird's Eye compatibility and does not enlarge
the native daemon v1 inventory. The adapter's `api.version` reports rustbgpd
product identity, not a Bird's Eye version promise.

See the [interop contract description](../interop.md#ixp-looking-glass-contract-oracle)
for the tested boundary, upstream pins, and unsupported behavior.

## Upgrade navigation

- Daemon operators: read the [CHANGELOG](../../CHANGELOG.md), the
  [v1 compatibility rules](v1-stable-contract.md#compatibility-rules), and the
  [deployment upgrade procedure](../how-to/deployment.md#upgrade).
- Rust embedders: follow the
  [published-crate release boundary](embedding.md#7-published-crate-release-boundary).
- Adapter operators: follow the pinned
  [Bird's Eye contract oracle](../interop.md#ixp-looking-glass-contract-oracle).
