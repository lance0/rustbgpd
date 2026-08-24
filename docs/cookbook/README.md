# Cookbook — scenario-driven deployment recipes

Choose a complete rustbgpd deployment recipe.

Each recipe here is a complete deployment shape: a working config, the
verification commands with the output shape to expect, the metrics to
watch, and the failure modes with the explain commands that debug them.
The configs are derived from the interop fixtures under
[`tests/interop/configs/`](../../tests/interop/configs/) that the
M-series receipts run against real peer stacks — every recipe cites the
receipts that prove its scenario ([`RECEIPTS.md`](../RECEIPTS.md)).

## IXP provisioning: three modes

An exchange provisions a rustbgpd route server in exactly one of three
mutually exclusive shapes. Pick by what you already have; each row's
recipe names the other two.

| Mode | You have… | The pipeline | Recipe | Proven by |
|------|-----------|--------------|--------|-----------|
| **Hand-written** | nothing external — you author members and policy yourself | [`examples/route-server/config.toml`](../../examples/route-server/config.toml) → `rustbgpd --check --strict` → SIGHUP | [IXP route server](route-server.md) | M83 |
| **ARouteServer-driven** | arouteserver's `general.yml` / `clients.yml` and its refresh cadence | `arouteserver template-context` → `rs-config-render` → `--check --strict` → swap + SIGHUP, fail-stale | [IXP filter pipeline](ixp-filter-pipeline.md) | M83, M90 (11/11 BIRD differential parity) |
| **IXP Manager-driven** | IXP Manager v7.4 as the member and router database | Foil template → `rs-config-render --input-format ixp-manager-v2` → `--check --strict` receipt → atomic activation with rollback → IXP Manager lock/fetch/callback lifecycle, `rustbgpd@<handle>.service` per handle | [IXP Manager route server](ixp-manager-route-server.md) | M96, M97 (local gates), pinned v7.4 contract oracle |

The renderer owns the whole output directory in both automated modes, so
you do not hand-edit their output, and IXP Manager mode activates only
unmodified receipted candidates. Piloting any mode beside your incumbent
with zero blast radius is the [shadow pilot](route-server-shadow-pilot.md);
two instances of any mode are [paired route servers](paired-route-servers.md).

| Recipe | When this is you | Proven by |
|--------|------------------|-----------|
| [iBGP route reflector at scale](route-reflector.md) | Replacing an iBGP full mesh; tens to 1,000 clients | M14, M76, M77, [1000-peer scale receipt](../perf/scale-receipt-2026-07.md) |
| [L3VPN route reflector](l3vpn-route-reflector.md) | VPNv4/VPNv6 reflection for a PE fleet, RT-Constrain filtered | M74, M75, M77, [VPN scale receipt](../perf/scale-receipt-2026-07.md) |
| [IXP route server](route-server.md) | Transparent redistribution among exchange members: RPKI, RFC 9234 roles, Add-Path + per-client best-path | M83 |
| [Route-server migration](route-server-migration.md) | Map FRR, BIRD, and ARouteServer concepts into rustbgpd and run a shadow-trial cutover | M83 |
| [Route-server shadow pilot](route-server-shadow-pilot.md) | Run rustbgpd for weeks as a receive-only, non-authoritative second route server beside production BIRD/OpenBGPD — the receive-only posture per provisioning mode (hand-written, arouteserver overlay, and what an IXP Manager site does instead), standing comparison loop, what a pilot cannot get yet, data-return contract, clean teardown | M83, M90, [IXP receipt matrix](../perf/ixp-matrix-2026-07.md); M96/M97 referenced for the cutover-shaped stack |
| [IXP filter pipeline](ixp-filter-pipeline.md) | Keep your arouteserver `general.yml`/`clients.yml`: render member filters with `rs-config-render`, reload fail-stale, serve Alice-LG | M83, M90 |
| [IXP Manager route server](ixp-manager-route-server.md) | IXP Manager v7.4 provisions the route server: Foil export → render → `--check --strict` receipt → atomic activation → lock/fetch/callback lifecycle, paired handles, IXP Manager looking glass through the Birdwatcher surface — with the boundary stated | M96, M97 (local), pinned v7.4 contract oracle |
| [MANRS IXP Action 1](manrs-ixp-action1.md) | Document your MANRS IXP Programme participation: Action 1 mapped requirement-by-requirement to validated config and member-verifiable surfaces | M83, fragments pass `rustbgpd --check --strict` |
| [Controller / monitoring feed](monitoring-feed.md) | Streaming BMP, durable events, and MRT into a controller or collector stack | M24, M81 |
| [EVPN fabric route reflector](evpn-fabric-rr.md) | Control-plane-only RR for a VXLAN-EVPN leaf/spine fabric | M29, M30, M82, M33 |
| [Policy quickstart (`.rpol`)](policy-quickstart.md) | First typed policy: tests, dry-run, hot swap, explain | M80, M34 |

Operator runbooks — short, ordered checklists for a live daemon:

| Runbook | When to reach for it |
|---------|----------------------|
| [Peer-flap triage](peer-flap-triage.md) | A session keeps cycling: confirm, read events, match the teardown reason, contain |
| [RR pair day-2](rr-pair-day2.md) | Routine changes on a redundant RR pair: GR sanity, adding clients, hot vs session-reset edits, commit-confirm |
| [Paired route servers](paired-route-servers.md) | Two independent RS instances: staggered config rollout, inter-RS consistency via `rbgp diff advertised`, RFC 8326 maintenance drain |
| [Activation manual recovery](activation-manual-recovery.md) | The activation or lifecycle helper returned exit 5 (`ManualRecovery`): confirm candidate health, keep or roll back, release the lifecycle lock, handle the receipt, resume automation |
| Shadow cutover | The step-by-step shadow trial lives in [route-server-migration.md](route-server-migration.md); the comparison tool it gates on is [`rbgp diff advertised`](../ribdiff.md) |

Conventions:

- Addresses are examples (RFC 5737 / private ranges) — substitute your
  own. No config here references a hostname.
- Every config in this directory's recipes loads through the real
  config loader: validated with `rustbgpd --check` and a daemon
  startup on the same commit that shipped them.
- gRPC in the recipes stays on the default local Unix socket with tier
  authorization ([ADR-0064](../adr/0064-grpc-authorization.md)). For
  remote access, see the mTLS guidance in [`SECURITY.md`](../SECURITY.md).
- Start here if you haven't run the daemon at all yet:
  [`docs/QUICKSTART.md`](../QUICKSTART.md), then come
  back for your scenario.
- Debugging why a route was (not) selected, advertised, or imported?
  The explain-surface catalog is [`docs/explain.md`](../explain.md).
