# ADR-0039: Transparent Route Server Mode

**Status:** Accepted
**Date:** 2026-03-04

## Context

The primary target deployment for rustbgpd is an IX route server. In that
role, outbound eBGP advertisements should often be transparent:

- preserve the original `NEXT_HOP`
- avoid automatically prepending the route server's local ASN

The default eBGP export path in rustbgpd intentionally does the opposite:

- prepends the local ASN
- rewrites next hop to self

That behavior is correct for ordinary eBGP peering, but not for route-server
clients.

## Decision

Add a static per-neighbor boolean:

- `route_server_client: bool`

When enabled for an **eBGP** neighbor:

- outbound **unicast** advertisements preserve the original next hop by
  default
- outbound **unicast** advertisements skip the automatic transport-layer
  local-AS prepend
- explicit export-policy next-hop overrides still win
- `LOCAL_PREF` is still stripped, because the peer is still eBGP

This behavior applies to:

- classic IPv4 unicast
- IPv4 unicast over IPv6 next hop (RFC 8950)
- IPv6 unicast

Validation rejects `route_server_client = true` on iBGP neighbors.

The feature is config-driven only in this first pass:

- static TOML config supports it
- dynamic peers added via gRPC default to `false`

FlowSpec is explicitly out of scope for this ADR:

- FlowSpec still uses the standard automatic eBGP `AS_PATH` prepend behavior
- transparent FlowSpec export is deferred

## Consequences

### Positive

- rustbgpd now supports the expected transparent eBGP export behavior for IX
  route-server clients
- RFC 8950 and IPv6 unicast follow the same transparent-next-hop rule, so
  dual-stack route-server deployments behave consistently
- the change is narrowly scoped to outbound transport rewrite behavior; no RIB
  or route-selection redesign is required

### Negative

- Dynamic peers cannot enable transparent route-server mode yet because the
  gRPC schema was intentionally left unchanged
- FlowSpec remains non-transparent until a follow-up change extends the same
  semantics there

### Neutral

- Explicit export-policy next-hop rewrites remain authoritative and can still
  force next-hop-self or a specific next hop even for route-server clients
