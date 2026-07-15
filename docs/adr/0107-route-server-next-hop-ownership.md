# ADR-0107: Route-server NEXT_HOP ownership

**Status:** Proposed
**Date:** 2026-07-15

## Context

RFC 7947 requires a route server to preserve `NEXT_HOP`, because it brokers
reachability but does not forward traffic. That transparency also amplifies a
bad client announcement: RFC 7948 section 4.8 describes how one member can
redirect traffic to another member's address and recommends an ownership
check on received next hops.

rustbgpd currently provides transparency, not ownership enforcement. Its
unicast receive and route-server export pipeline is:

1. decode the wire `NEXT_HOP` or `MP_REACH_NLRI` next-hop tuple;
2. evaluate import policy against that original decoded value;
3. permit import policy to rewrite the next hop;
4. store the resulting next hop on the accepted route; and
5. preserve that stored value on transparent route-server export unless
   export policy supplies another rewrite.

Within an UPDATE evaluation the decoded value is the immutable wire input, but
it is not retained separately after an accepted import rewrite. Import policy
can match or rewrite a next hop; a rewrite does not prove that the advertising
client owns it. No built-in ownership gate performs this validation today.

## Decision

### 1. Pilot an explicit, fail-closed strict-peer mode

Design the first implementation as an opt-in mode, called `strict_peer` in
this ADR only. That name is conceptual, not shipped configuration syntax. The
pilot accepts a unicast announcement only when every address component in its
wire next-hop identity belongs to the advertising session itself.

This deliberately narrow rule is not a claim that address equality is the
only valid IXP policy. RFC 7948 explicitly permits an organization to use a
different connection in the same AS. Two broader modes remain deferred:

- **same-AS:** allow an address owned by another established session whose
  OPEN-negotiated ASN equals the advertising session's negotiated ASN; and
- **explicit-authorized:** allow an operator-approved address relationship.

Both require an immutable, generation-consistent authoritative fleet
inventory. Its authority is the ASN negotiated from OPEN and the address
identity bound to each live session generation. A configured wildcard ASN and
the route's `AS_PATH` are never ownership evidence.

### 2. Define the complete wire identity

The check must operate on the decoded wire form, not a lossy `IpAddr` alone:

- classic IPv4 unicast has one IPv4 `NEXT_HOP` address;
- IPv6 unicast can carry one global IPv6 address or a global plus link-local
  pair;
- RFC 8950 IPv4-over-IPv6 uses the same 16- or 32-octet IPv6 forms; and
- a link-local primary or companion is identified by address plus interface
  scope. The same `fe80::/10` value on two interfaces is not one identity.

The strict pilot rejects any form whose complete identity cannot be mapped to
the advertising session. In particular, it must not silently discard or
ignore an unverified link-local companion. The later inventory must preserve
primary/companion structure and scope rather than flattening addresses.

### 3. Enforce before import policy and preserve replacement semantics

Future enforcement inspects the immutable decoded wire value before import
policy can rewrite it. A policy rewrite cannot turn an unauthorized input into
an authorized one or obscure what was checked.

The gate follows existing pre-policy replacement behavior. If a rejected
announcement replaces an accepted route, remove the exact prior
`(prefix, path_id)` identity. A first-seen rejection emits no withdrawal.
This prevents a rejected replacement from leaving stale reachability while
remaining correct for Add-Path.

### 4. Use one bounded reason vocabulary

Metric, event, log, and import-explain output use one typed, low-cardinality
reason vocabulary. Explain identifies the decision as a **pre-policy next-hop
ownership rejection**, not an import-policy denial.

Metrics may label only the typed reason. Observed peer, prefix, next-hop tuple,
scope, and session generation belong in structured event/log fields and must
never become metric labels. Inventory-unavailable or generation-mismatch
cases fail closed when an ownership mode is enabled.

### 5. BLACKHOLE is not an ownership bypass

RFC 7999 does not grant a next-hop-ownership exception. A BLACKHOLE
announcement is accepted only when all three checks hold: next-hop address
authorization, prefix authorization, and explicit operator agreement to honor
BLACKHOLE on that session. A community alone cannot bypass the ownership
gate.

### 6. Keep the feature in the route-server niche

This is an ingress authorization check, not a reachability oracle. It will not
perform FIB or recursive-next-hop resolution, ARP/ND inspection, PE behavior,
ordinary route-reflector/iBGP enforcement, or broad AFI/SAFI expansion. The
pilot covers only the shipped IPv4/IPv6 unicast route-server forms above.

## Implementation gate

Before the strict pilot, specify the advertising session's immutable identity
snapshot, generation handoff, and removal behavior. Before either broader
mode, specify the authoritative fleet inventory's producer and atomic view at
UPDATE evaluation. Then prove:

1. every wire form and scoped identity above is accepted or rejected without
   normalization ambiguity;
2. policy rewrites occur only after ownership succeeds;
3. a rejected replacement removes only its exact prior identity;
4. same address/different interface and same configured wildcard/different
   negotiated ASN cannot cross-authorize; and
5. all observability surfaces share the same bounded reason.

Do not expose a configuration key until those invariants and a real IXP pilot
transcript are load-bearing tests. Same-AS and explicit authorization remain a
separate decision after the strict pilot.

## Consequences

- Operators have an honest map of today's transparent-but-unchecked behavior.
- A small strict pilot can close the common hijack case without pretending to
  support legitimate alternate next hops prematurely.
- Same-AS traffic engineering remains possible by design, but waits for the
  inventory needed to authorize it safely.
- The future hot-path check is bounded lookup work; inventory publication and
  generation consistency carry the main implementation complexity.

## References

- RFC 7947, sections 2.1 and 2.2.1: <https://www.rfc-editor.org/rfc/rfc7947.html>
- RFC 7948, sections 4.2.1.3 and 4.8: <https://www.rfc-editor.org/rfc/rfc7948.html>
- RFC 7999, sections 3.3 and 6: <https://www.rfc-editor.org/rfc/rfc7999.html>
- RFC 8950, section 3: <https://www.rfc-editor.org/rfc/rfc8950.html>
- [ADR-0039](0039-transparent-route-server.md), transparent route-server mode
