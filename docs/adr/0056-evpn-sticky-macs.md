# ADR-0056: EVPN sticky-MAC operator config

**Status:** Accepted
**Date:** 2026-05-08

## Context

ADR-0055 §8 deferred operator-facing per-MAC sticky configuration:

> Operator-facing per-MAC sticky configuration is **explicitly out of
> scope** for this ADR; the sticky field is plumbed end-to-end (state
> machine → Inject action → wire codec) but always `false` on the
> daemon side until a follow-up ADR defines the config schema.

That follow-up is now load-bearing. With Gate 7b+1 shipped in v0.15
and the bidirectional VTEP loop polished in v0.16, the sticky bit is
the only RFC 7432 §15.4 field with no operator-facing surface. Until
operators can pin a MAC, the daemon emits *every* Type 2 with no
sticky bit, which means a misconfigured peer that announces with
`seq=N` for an operator's gateway MAC silently wins best-path and
black-holes traffic until manual intervention. RFC 7432 §15.4 sticky
is the standardized defense; we already plumb the bit, we just have
no way to ask for it.

The wire codec (`crates/wire/src/extended_community.rs`) and state
machine (`crates/evpn/src/origination.rs`) accept the bit through
`OriginationAction::Inject { sticky, .. }` and
`LocalMacOriginator::on_local_learned(.., sticky, ..)`. The hardcoded
`false` in `src/evpn_originator.rs::handle_observation` is the only
gap. The schema choice for *how* operators set it is what this ADR
locks.

## Decision

### Naming: `sticky_macs`, not `static_macs`

> rustbgpd does **not** install static FDB entries and does **not**
> originate these MACs unless the kernel learns them on a local
> bridge port. The flag's only effect is that, when the kernel does
> learn one of these MACs, the corresponding Type 2 is emitted with
> the MAC Mobility extended community's sticky bit set (RFC 7432
> §15.4). Calling these `static_macs` would over-promise;
> `sticky_macs` is the precise term FRR / Cumulus / Junos use.

The TOML key is `sticky_macs`. The runtime field on `EvpnInstance` is
`sticky_macs: BTreeSet<MacAddress>`.

### Schema shape: inline list of canonical MACs

```toml
[[evpn_instances]]
vni = 10100
rd = "65000:10100"
route_targets = ["65000:10100"]
local_vtep_ip = "10.10.10.1"
sticky_macs = [
  "aa:bb:cc:dd:ee:01",   # leaf-01 anycast gateway
  "aa:bb:cc:dd:ee:02",   # leaf-02 anycast gateway
]
```

The list contains lowercase, colon-separated, six-octet MAC strings
(`aa:bb:cc:dd:ee:ff`). Empty list (`sticky_macs = []`) is equivalent
to omission. Default is empty.

Validation:

- Each entry must parse as a 48-bit MAC. Malformed strings are
  rejected with a `vni N: invalid sticky_mac "..."` error.
- Duplicates within one instance's list are rejected (typo guard).
- The same MAC across two VNIs is allowed — separate L2 domains.

### Rejected alternatives

- **Sub-table form (`[[evpn_instances.sticky_mac]] mac = "..."`).**
  Pure verbosity tax for a list of opaque values; we'd add no fields
  per entry today, and adding them later doesn't require this shape.
- **Sysctl / kernel FDB import.** The kernel `extern_learn` /
  `permanent` FDB attributes are **dataplane policy** about whether
  to age out the entry, not BGP semantics. Reading them would couple
  the daemon to a specific Linux release and conflate two different
  knobs. Operators who want both signals can program both
  independently.
- **External file include (`sticky_macs_file = "..."`).** Avoids
  inlining long lists, but defers the same parse to a second
  format. Operators can already split a long list across multiple
  TOML lines.
- **Adding `MacAddress::FromStr` to `crates/wire`.** Tempting for
  ergonomics but bumps the published wire crate for one-line
  ergonomics. The MAC parser stays in `src/config/mod.rs` —
  RFC 7432 NLRI uses raw bytes, not the operator notation, so the
  wire crate has no need for the `FromStr` impl.

### Restart semantics

`sticky_macs` lives inside `EvpnInstanceConfig` and is part of the
`old.evpn_instances != new.evpn_instances` comparison `diff_config`
already performs. Any change to the list flips
`evpn_instances_changed`, which `--diff` surfaces under the
restart-required bucket. That matches the other
`[[evpn_instances]]` fields (`vni`, `rd`, `route_targets`,
`local_vtep_ip`, `bridge`, `advertise_svi_mac`).

The restart-required choice is deliberate. Hot-reloading
`sticky_macs` would require resequencing already-advertised Type 2s
to add or clear the bit, which is exactly the kind of in-flight
sequence rewrite RFC 7432 §15.1 is structured to avoid. A daemon
restart re-originates from a clean state and the new sticky markings
take effect on the next kernel learn — the simplest correct answer.

### Quarantine scope

ADR-0055 §9 now ships local-origin suppression for duplicate-MAC-move
detection. With `action = "suppress_local"`, the originator withdraws
and suppresses locally-originated Type 2 routes for the offending
`(VNI, MAC)` until timed recovery. Sticky-bit origination remains an
independent operator signal: an operator's sticky MAC and a contender
at higher seq still produce normal best-path movement unless duplicate
MAC detection is separately enabled. Future work tracked in
`docs/evpn-alpha-soak.md` / #139 will add remote-route processing and
dataplane loop-protection.

## Consequences

**Positive.**
- Operators can set the RFC 7432 §15.4 sticky bit on origination
  with a one-line config change, no daemon code edits or out-of-band
  policy.
- The schema lives in `EvpnInstanceConfig` so it's covered by the
  existing config validation, `--diff`, and restart-required
  surfaces with no new infrastructure.
- The naming distinguishes the daemon's behavior (mark on
  origination) from kernel static-FDB programming, which it
  intentionally does not do.

**Negative.**
- Operators with very long MAC lists must inline them in TOML.
  Acceptable for the scale rustbgpd targets (typically per-VNI lists
  measure in tens, not thousands); a future `sticky_macs_file`
  include can be added as a backwards-compatible second field
  without revisiting this ADR.
- Hot-reload is not supported. Operators must restart the daemon
  to pick up `sticky_macs` changes. See "Restart semantics" above
  for the rationale.

## Implementation references

- `src/config/schema.rs` — `EvpnInstanceConfig.sticky_macs: Vec<String>`
- `src/config/mod.rs::parse_evpn_instance` — parse + validation
- `src/config/mod.rs::parse_mac_address` — `aa:bb:cc:dd:ee:ff`
  parser local to the daemon
- `crates/evpn/src/instance.rs` —
  `EvpnInstance.sticky_macs: BTreeSet<MacAddress>` +
  `with_sticky_macs` setter
- `src/evpn_originator.rs::handle_observation` — consults
  `inst.sticky_macs.contains(&mac)` on `LocalMacObservation::Learned`

## Reference

- RFC 7432 §15.4 — Sticky bit in MAC Mobility extcomm
- ADR-0054 — EVPN Linux dataplane boundary
- ADR-0055 §8 — Deferred sticky schema (closed by this ADR)
- `examples/evpn-vtep-leaf/config.toml` — annotated example
