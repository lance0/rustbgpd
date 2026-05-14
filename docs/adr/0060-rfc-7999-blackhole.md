# ADR-0060: RFC 7999 BLACKHOLE receiver scoping and opt-in FIB discard

**Status:** Accepted
**Date:** 2026-05-13

## Context

RFC 7999 defines the well-known `BLACKHOLE` community
(`65535:666` / `0xFFFF_029A`) as a signal that traffic to the attached
destination prefix should be discarded. The usual operational use is
RTBH: a customer, edge router, or mitigation controller advertises a
specific host route with `BLACKHOLE`; the receiving AS scopes the route
and optionally installs a discard entry close to the attack source.

rustbgpd already has the policy machinery to match and set standard
communities, and it has an EBGP import-chain mechanism for implicit
receiver behavior such as RFC 8326 Graceful Shutdown. It does not yet
own a generic unicast FIB programming path outside the EVPN Linux
dataplane. Installing kernel discard routes for `BLACKHOLE` would
therefore be a new dataplane feature with real blast radius, not just a
policy alias.

## Decision

### 1. Wire value is centralized in the wire crate

`crates/wire` owns `COMMUNITY_BLACKHOLE = 0xFFFF_029A` alongside the
other RFC-assigned standard communities. The policy engine, CLI
formatting, tests, and future dataplane code all depend on that single
constant rather than open-coding `65535:666`.

### 2. Policy alias works wherever standard communities are parsed

`parse_community_match` accepts `"BLACKHOLE"` as an alias for
`65535:666`. Because the daemon's set-side parser routes through the
same helper, the alias works in both `match_community` and
`set_community_add` / `set_community_remove`.

### 3. Receiver behavior is opt-in and EBGP-only

`[global] honor_blackhole = true` appends an implicit import-chain tail
rule for EBGP neighbors:

```text
match community = BLACKHOLE -> permit, add BLACKHOLE + NO_ADVERTISE
```

The rule preserves `BLACKHOLE` and adds `NO_ADVERTISE` so the route is
scoped at the receiver boundary. Running the rule at the chain tail
allows explicit operator import policy to reject unsafe prefixes first
and still lets the implicit rule add the scoping community to accepted
routes.

The rule is EBGP-only. iBGP propagation inside the local AS should carry
the already-scoped route; reapplying the receiver rule at every iBGP hop
would make local route-server and route-reflector behavior harder to
reason about.

### 4. SIGHUP hot-applies the policy-only knob

When kernel discard installation is disabled, `honor_blackhole` is not
pinned to startup. Reload sends `PeerManagerCommand::SetHonorBlackhole`,
advances the live config snapshot, and recomputes peer import chains
through the same runtime policy update path as `honor_graceful_shutdown`.

When either the live or requested config has
`install_blackhole_discard = true`, `honor_blackhole` is part of the
reconciler spawn gate (`honor_blackhole && install_blackhole_discard`).
SIGHUP pins it to the live snapshot and asks the operator to restart
rather than silently advancing the control-plane setting without
starting or stopping the kernel-discard actor.

### 5. Kernel discard is a second explicit opt-in

`honor_blackhole = true` remains control-plane scoping only. Kernel
discard installation is enabled only when the operator also sets:

```toml
[global]
install_blackhole_discard = true
```

The daemon starts a unicast BLACKHOLE reconciler at boot when both
`honor_blackhole` and `install_blackhole_discard` are true. The
reconciler subscribes to unicast best-path events, periodically
re-queries the Loc-RIB as a level-triggered backstop, and installs
kernel `RTN_BLACKHOLE` routes only for accepted best routes that still
carry the RFC 7999 community after import policy.

The first FIB slice is deliberately conservative:

- **Authorization:** which peers or peer-groups are allowed to request
  discard installation. Today the daemon requires the route to be
  EBGP-learned and still carry `BLACKHOLE` after operator policy; iBGP
  routes are visible but rejected from local FIB install.
- **Prefix bounds:** default to host-route-only (`/32` and `/128`) and
  require `allow_blackhole_broad_prefixes = true` for broader drops.
- **Failure discipline:** a failed discard install must not make the
  control plane claim enforcement succeeded. Failures are surfaced in
  `rustbgpctl rib blackholes` and Prometheus counters.
- **Blast-radius controls:** rate limits, maximum active blackholes,
  and a richer operator-visible audit trail remain follow-ups.
- **Idempotent cleanup:** route withdrawal, policy rejection, peer flap,
  and daemon shutdown remove only discard state installed by this daemon
  lifetime.

Existing kernel routes for the same prefix are not overwritten. The
Linux implementation issues `RTM_NEWROUTE` without replace semantics;
`EEXIST` is an install failure, preserving static routes and other
routing daemons' FIB ownership.

`install_blackhole_discard`, `allow_blackhole_broad_prefixes`, and the
`honor_blackhole` component of an enabled or requested FIB-discard spawn
gate are startup-only. SIGHUP pins them to the live snapshot and asks
the operator to restart, matching the reconciler's one-shot spawn model.

## Consequences

Positive:

- Operators can express RFC 7999 policy by name instead of using a
  numeric community literal.
- Receivers can scope EBGP `BLACKHOLE` routes with one global opt-in.
- The CLI renders `65535:666` as `BLACKHOLE`, making route inspection
  less error-prone.
- The default behavior remains safe for route reflectors and route
  servers because it does not mutate the local kernel FIB.
- Operators that explicitly opt into FIB enforcement get bounded local
  RTBH behavior with host-route defaults and owned cleanup.

Negative:

- `honor_blackhole` alone does not mitigate traffic on the local host;
  operators must enable `install_blackhole_discard` separately.
- The first FIB slice does not implement rate limits or per-peer
  allow-lists beyond EBGP + import-policy acceptance.

Neutral:

- Explicit import policy remains the right place to enforce host-route
  restrictions and peer authorization today.
- FIB discard reuses the same wire constant and policy alias without
  changing the control-plane contract.

## What we rejected

- **Implicit kernel discard under `honor_blackhole`.** Too much blast
  radius. FIB enforcement requires `install_blackhole_discard = true`.
- **Overwriting existing kernel routes.** `replace` would be convenient
  for idempotency, but it could silently steal a static route or another
  daemon's route. We preserve foreign routes by treating `EEXIST` as a
  failed install and surfacing it.
- **Denying BLACKHOLE routes by default.** That prevents route servers
  and mitigation controllers from carrying the signal to the device that
  will actually enforce it.
- **Using `0:666` as the canonical value.** Some deployments use local
  conventions, but RFC 7999 reserves `65535:666`.
- **Head-of-chain implicit policy.** Explicit operator policy must be
  able to reject broad or unauthorized BLACKHOLE prefixes before the
  implicit scoping rule runs.

## Cross-references

- RFC 7999 — BLACKHOLE Community.
- `crates/wire/src/lib.rs` — `COMMUNITY_BLACKHOLE`.
- `crates/policy/src/engine.rs` — community alias parser.
- `src/config/mod.rs` — `build_implicit_blackhole_policy` and effective
  import-chain assembly.
- `src/peer_manager.rs` — `set_honor_blackhole` hot-apply fan-out.
- `src/blackhole.rs` — opt-in kernel discard reconciler.
- `examples/ddos-mitigation/config.toml` — RTBH operator example with
  explicit host-route guard policy.
