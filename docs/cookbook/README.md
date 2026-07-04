# Cookbook — scenario-driven deployment recipes

Each recipe here is a complete deployment shape: a working config, the
verification commands with the output shape to expect, the metrics to
watch, and the failure modes with the explain commands that debug them.
The configs are derived from the interop fixtures under
[`tests/interop/configs/`](../../tests/interop/configs/) that the
M-series receipts run against real peer stacks — every recipe cites the
receipts that prove its scenario ([`RECEIPTS.md`](../RECEIPTS.md)).

| Recipe | When this is you | Proven by |
|--------|------------------|-----------|
| [iBGP route reflector at scale](route-reflector.md) | Replacing an iBGP full mesh; tens to 1,000 clients | M14, M76, M77, [1000-peer scale receipt](../perf/scale-receipt-2026-07.md) |
| [L3VPN route reflector](l3vpn-route-reflector.md) | VPNv4/VPNv6 reflection for a PE fleet, RT-Constrain filtered | M74, M75, M77, [VPN scale receipt](../perf/scale-receipt-2026-07.md) |
| [IXP route server](route-server.md) | Transparent redistribution among exchange members: RPKI, RFC 9234 roles, Add-Path + per-client best-path | M19, M83 |
| [Controller / monitoring feed](monitoring-feed.md) | Streaming BMP, durable events, and MRT into a controller or collector stack | M24, M81 |
| [EVPN fabric route reflector](evpn-fabric-rr.md) | Control-plane-only RR for a VXLAN-EVPN leaf/spine fabric | M29, M30, M82, M33 |
| [Policy quickstart (`.rpol`)](policy-quickstart.md) | First typed policy: tests, dry-run, hot swap, explain | M80, M34 |

Conventions:

- Addresses are examples (RFC 5737 / private ranges) — substitute your
  own. No config here references a hostname.
- Every config in this directory's recipes loads through the real
  config loader: validated with `rustbgpd --check` and a daemon
  startup on the same commit that shipped them.
- gRPC in the recipes stays on the default local Unix socket with tier
  authorization ([ADR-0064](../adr/0064-grpc-authorization.md)). For
  remote access, see the mTLS guidance in [`SECURITY.md`](../SECURITY.md).
- Start here if you haven't run the daemon at all yet: the README
  [quick start](../../README.md#quick-start-bare-metal), then come
  back for your scenario.
