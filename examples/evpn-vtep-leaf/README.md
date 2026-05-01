# EVPN VTEP leaf (Phase-2 foundation)

Leaf-mode rustbgpd config: an iBGP peering to one or more spine route
reflectors, plus three local **EVPN instances** declared in TOML. This
is the operator-facing surface of Gate 7a (ADR-0052) — the
**declarative** half of VTEP mode. Kernel FDB learning, local MAC
origination, and Type 2/3 emission from these instances land with
Gate 7b (see [`docs/evpn-enablement.md`](../../docs/evpn-enablement.md)).

For the route-reflector counterpart — same fabric, no local EVIs —
see [`../rr-evpn-fabric/`](../rr-evpn-fabric/).

## What this example demonstrates

- **iBGP session to a spine RR** with `families = ["l2vpn_evpn"]`. No
  local EVI state on the RR; the leaf owns its own.
- **Three `[[evpn_instances]]` blocks** showing the full operator
  surface:
  - **VNI 10100** — the minimal shape: `vni`, `rd`, `route_targets`,
    `local_vtep_ip`. Optional `bridge` set to `br100` for the future
    kernel-reconciliation slice.
  - **VNI 10200** — adds `advertise_svi_mac = true` (RFC 9135 §6.1).
    Today the flag parses and surfaces in `rustbgpctl evpn
    instances`; it drives Type 2 origination once Gate 7b ships.
  - **VNI 10300** — uses a 4-octet AS in the RD (`4200000000:300` →
    RFC 4364 Type 2 RD); two route targets to demonstrate the
    bidirectional list (deduplicated and canonicalized on
    resolution).

## Verifying the config

```bash
# Validate the schema, RD/RT parsing, VTEP-IP unicast check, and
# uniqueness invariants without starting the daemon.
rustbgpd --check examples/evpn-vtep-leaf/config.toml

# Preview against another config.
rustbgpd --diff examples/rr-evpn-fabric/config.toml \
                examples/evpn-vtep-leaf/config.toml
```

`[[evpn_instances]]` edits are surfaced as **restart-required** in
`--diff`. The runtime gRPC `EvpnService` shares the resolved instance
table via an `Arc` built once at startup; the foundation slice has
no SIGHUP swap surface (intentional — see ADR-0052 §Boundaries).

## Inspecting at runtime

```bash
# Human format
rustbgpctl evpn instances

# JSON for scripting
rustbgpctl evpn instances --json
```

Expected output (human format):

```
vni=10100 rd=10.0.0.10:10100 vtep=10.0.0.10 rts=[65000:10100] bridge=br100
vni=10200 rd=10.0.0.10:10200 vtep=10.0.0.10 rts=[65000:10200] bridge=br200 advertise-svi-mac
vni=10300 rd=4200000000:300 vtep=10.0.0.10 rts=[65000:10300,65000:55000]
```

## What this example does NOT do (yet)

- Program kernel VXLAN devices, bridges, or FDB entries.
- Originate Type 2 (MAC/IP), Type 3 (IMET), or Type 5 (IP Prefix)
  routes from the local instance. The RR will see this leaf as a
  consumer, not a contributor, until Gate 7b lands.
- React to MAC learn / age events on the kernel FDB.
- Mediate MAC mobility per RFC 7432 §15 — that's a Gate 7b concern
  with explicit domain types in `crates/evpn`, not via wire route
  overload.

## Related

- [`../rr-evpn-fabric/`](../rr-evpn-fabric/) — RR-side counterpart
- [`../../docs/adr/0052-evpn-vtep-foundation.md`](../../docs/adr/0052-evpn-vtep-foundation.md) — boundaries between this slice and the future dataplane crate
- [`../../docs/evpn-enablement.md`](../../docs/evpn-enablement.md) — Gate 7a / 7b roadmap
- [`../../KNOWN_ISSUES.md`](../../KNOWN_ISSUES.md) — `[[evpn_instances]]` SIGHUP semantics
