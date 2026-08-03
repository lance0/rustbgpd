# ADR-0118: Presence-preserving runtime neighbor creation

**Status:** Accepted — fully shipped
**Date:** 2026-07-29

> **Server and CLI tranches shipped.** The daemon preserves the wrapper and
> `rbgp neighbor add` sends it exclusively with explicit negative forms and a
> fail-closed old-server diagnostic.

## Context

`NeighborService.AddNeighbor` accepts an optional `NeighborConfig config = 1`.
The message predates runtime peer-group inheritance and uses implicit-presence
proto3 scalars and repeated fields. It therefore cannot distinguish omission
from an explicit `false`, zero, or empty list.

The API conversion currently resolves that ambiguity before the normal config
resolver can see it:

- `crates/api/src/neighbor_service.rs` maps an empty `families` list to explicit
  IPv4 unicast and maps implicit booleans to `false`;
- the same conversion materializes server defaults for TTL security, Graceful
  Restart, route-reflector-client, prefix ORF receive, and IPv6-only behavior;
- `src/policy_admin.rs` reconstructs a persisted `Neighbor` from that resolved
  `PeerManagerNeighborConfig`, writing explicit lists, booleans, and GR values;
- `src/peer_manager/lifecycle.rs` repeats that reconstruction in the
  actor-owned runtime config snapshot before calling the normal resolver.

Consequently, a request that only names a peer group can silently shadow group
values. The resolver itself is not defective: it already gives explicit
neighbor values precedence, then peer-group values, then computed defaults.
Presence has been lost before that precedence code runs.

The existing payload cannot be reinterpreted. Older clients may depend on empty
families becoming IPv4 and implicit booleans becoming explicit `false`.
`AddNeighbor` is in the v1 stable message graph, so its existing field number,
type, and source shape remain fixed.

Protocol Buffers documents adding a new field as wire-safe: old binaries skip
the unknown field. It also documents moving existing fields into an existing
`oneof` as unsafe and notes that implicit-presence scalars cannot distinguish
an omitted value from the default. See the
[proto3 language guide](https://protobuf.dev/programming-guides/proto3/).

## Decision

Add one presence-aware payload alongside, not around, the legacy field:

```proto
import "google/protobuf/field_mask.proto";

message NeighborCreateIntent {
  NeighborConfig config = 1;
  google.protobuf.FieldMask override_mask = 2;
}

message AddNeighborRequest {
  NeighborConfig config = 1;       // Legacy; unchanged and outside a oneof.
  NeighborCreateIntent intent = 2; // Presence-aware create contract.
}
```

The exact message names may be adjusted for generated-language clarity, but the
wire and behavioral constraints above are fixed:

1. `AddNeighborRequest.config` remains field 1 with its current type and is not
   moved into a `oneof`.
2. The presence-aware wrapper is field 2.
3. A new server requires exactly one of `config` and `intent`.
4. An intent requires both its inner `config` and an `override_mask`. A present
   mask with an empty `paths` list is valid.
5. New clients send intent only. They never send both payloads and never retry
   a rejected intent as legacy config.

The FieldMask applies directly to the inner `NeighborConfig`. Paths use the
lower-snake-case protobuf field names. Wildcards, nested paths, duplicate
paths, and unknown paths are rejected before config persistence or runtime
mutation.

This is a create-override mask, not a resource-update mask. Values outside the
mask do not become neighbor overrides. Masked repeated family fields replace,
rather than append to, inherited lists. This service-specific behavior is
documented here because the standard FieldMask update behavior otherwise
merges messages and appends repeated values. The
[FieldMask reference](https://protobuf.dev/reference/java/api-docs/com/google/protobuf/FieldMask)
also establishes that a mask can select a scalar set to its default value and
that an API may require a mask.

### Rolling compatibility

| Client | Server | Request payload | Result |
|---|---|---|---|
| Legacy | Old | `config` only | Accepted with current legacy semantics |
| Legacy | New | `config` only | Accepted with exactly the same legacy conversion |
| New | New | `intent` only | Accepted with presence-aware semantics |
| New | Old | `intent` only | Rejected fail-closed before mutation |
| Any | New | Both | Rejected with `INVALID_ARGUMENT` before mutation |
| Any | Old | Both | The unknown intent is skipped and valid legacy config may be accepted |
| Any | Old or new | Neither | Rejected with `INVALID_ARGUMENT` |

An old daemon skips wrapper field 2, then its current handler sees field 1
absent and returns `INVALID_ARGUMENT` (`config is required`). The new CLI must
turn that response into a clear "daemon does not support presence-aware
neighbor creation" error. It must not downgrade: sending both or retrying
legacy would let an old daemon accept a neighbor after silently discarding the
presence contract.

The operational upgrade order is therefore server first. Old clients continue
to work against a new server. New-client neighbor creation is unavailable
against an old server, but it fails without changing runtime or disk state.

### Field contract

Five fields are direct create inputs and never appear in the mask:

| Field | Contract |
|---|---|
| `address` | Required, non-empty peer identity |
| `remote_asn` | Required and greater than zero |
| `interface` | Optional scoped-address identity component |
| `description` | Direct metadata; empty normalizes to absent |
| `peer_group` | Direct group reference; empty means no group |

The mask has a closed nine-path allow-list:

1. `families`
2. `required_families`
3. `route_server_client`
4. `per_client_best`
5. `strict_role`
6. `add_path_receive`
7. `add_path_send`
8. `add_path_send_max`
9. `paths_limit_receive_max`

`families` and `required_families` have replacement semantics:

- omitted path: inherit a non-empty peer-group value, then use the existing
  resolver fallback;
- masked non-empty list: explicit neighbor override;
- masked empty list: reject with `INVALID_ARGUMENT`.

An unmasked `families` value must be empty, and an unmasked
`required_families` value must be empty. Rejecting contradictory payloads keeps
the mask authoritative instead of silently ignoring data.

The three standalone booleans preserve explicit `false`:

- an omitted path inherits;
- a masked path stores `Some(value)`, including `Some(false)`.

Add-Path is one atomic override block, matching the config resolver's existing
`Option<AddPathConfig>` boundary. The four Add-Path paths must be all present
or all absent:

- all absent inherits the complete peer-group Add-Path block;
- all present creates one explicit block;
- `false`, `false`, `0`, `0` explicitly disables an inherited block;
- any partial quartet is rejected.

The remaining exposed fields retain their current presence or sentinel
contract and are not valid mask paths:

| Fields | Intent conversion |
|---|---|
| `hold_time` | zero remains unset/inherit; non-zero is explicit |
| `max_prefixes` | zero remains unset/inherit; non-zero is explicit |
| `remove_private_as` | empty inherits; a recognized non-empty mode overrides |
| `role` | empty inherits; a recognized non-empty role overrides |
| `send_hold_time` | protobuf optional presence is retained; present zero disables |
| `min_hold_time` | protobuf optional presence is retained |
| `max_prefix_restart_seconds` | protobuf optional non-zero presence is retained |

This tranche does not invent clear sentinels that the persisted config model
cannot represent. Empty role cannot clear an inherited role; empty
`remove_private_as` cannot disable an inherited mode; empty required families
cannot clear the group list; and absent optional hold/restart values cannot
clear inherited values. A future tri-state config design may add those
operations explicitly. This implementation must reject a mask that attempts to
claim such semantics.

Fields not exposed by `NeighborConfig` are absent in the raw intent. The normal
resolver may therefore inherit peer-group values for TTL security, GR and LLGR,
route-reflector client and ORR, prefix ORF, IPv6-only behavior, slow-peer
settings, per-family prefix limits, BFD, authentication, local IPv6 next-hop,
NEXT_HOP ownership, RFC 1997 and route-server control-community modes, log
level, and policy fields. The API layer must not materialize their defaults.

Omitted families on a presence-aware request use the normal config resolver all
the way through. With no group, an IPv4 neighbor defaults to IPv4 unicast and
an IPv6 neighbor defaults to IPv4 plus IPv6 unicast. The latter deliberately
differs from legacy `AddNeighbor`, which turns every empty family list into
IPv4 before resolution. This difference belongs to the new payload contract
and must be visible in CLI/API documentation when implementation ships.

### Raw carrier and ownership

A direct boxed raw carrier preserves presence until actor resolution:

```text
Box<PresenceAwareNeighborCreate>
```

The presence-aware form uses option/list/block shapes that map losslessly to a
raw config `Neighbor`; it is not a partially resolved transport config. The
same boxed raw carrier crosses both ownership boundaries:

1. `ConfigEvent::PresenceAwareNeighborAdded` carries it to the config bridge.
2. The bridge applies it to a cloned raw `Config`, runs `Config::validate`,
   and stages the exact candidate TOML.
3. `PeerManagerCommand::RuntimeCreatePeer` carries the same raw value to the
   actor.
4. PeerManager applies it to its actor-owned `current_config`, selects the raw
   neighbor, and invokes the existing resolver before spawning the session.
5. Only after runtime apply succeeds does the already-staged config publish.

The existing stage-then-apply-then-commit and cancellation-shielding behavior
does not change. A persistence, validation, or runtime failure creates neither
a durable neighbor nor a live peer.

Legacy `AddNeighbor`, startup, reconfigure, and delete rollback continue through
their existing resolved `PeerManagerNeighborConfig` paths without entering this
presence-aware carrier.

### Validation ordering

The gRPC layer validates envelope cardinality, mask shape, field syntax, peer
identity, and conversions that do not depend on inheritance. It must not
validate dependent values solely against the unmasked protobuf defaults.

The candidate raw config, after peer-group lookup, is authoritative for:

- `required_families` being a subset of effective families;
- `per_client_best` requiring effective route-server-client mode;
- `strict_role` requiring an effective role;
- route-server-only settings requiring eBGP;
- route-reflector-client settings requiring iBGP;
- Add-Path and Paths-Limit dependencies;
- GR, IPv6-only, ORF, and other existing config invariants.

The config bridge performs this validation before staging. PeerManager repeats
resolution against its actor-owned snapshot before spawning, closing the
runtime/persistence snapshot seam.

### CLI construction

`rbgp neighbor add` always sends the wrapper, even when its mask is empty.

- A non-empty `--families` or `--required-families` argument adds the
  corresponding path.
- Existing positive boolean flags add their path with value `true`.
- Additive, mutually exclusive `--no-*` forms are required where the CLI
  exposes an explicit `false` override.
- Any Add-Path flag emits all four mask paths and fills unspecified members
  with `false` or zero.
- An additive `--no-add-path` emits the complete disabled block and conflicts
  with every positive Add-Path option.
- The numeric Add-Path CLI members retain occurrence information rather than
  relying on unconditional parser defaults.

The CLI never probes by mutation and never retries as legacy after rejection.

## Required implementation proofs

The implementation is not complete without load-bearing tests for:

1. a frozen legacy decoder skipping wrapper field 2 and yielding legacy
   `config` absent;
2. a new server accepting legacy-only requests with exact current behavior;
3. both, neither, missing-inner-message, missing-mask, unknown-mask, duplicate,
   wildcard, nested, and partial-Add-Path requests failing before mutation;
4. a route-server group whose families, route-server flags, role, TTL, GR, and
   related values are inherited live, absent from persisted neighbor TOML, and
   identical after restart;
5. an iBGP route-reflector group whose client flag, cluster behavior, families,
   and GR state have the same live/persisted/restart proof;
6. masked `false`, non-empty family replacement, and an explicitly disabled
   Add-Path block surviving persistence and restart;
7. dependent validation accepting inherited prerequisites and rejecting the
   effective invalid candidate after resolution;
8. a new CLI sending wrapper-only, constructing exact masks, and refusing an
   old-server downgrade;
9. stable protobuf source assertions and a deliberately reviewed update to the
   v1 message-graph inventory.

The tests must be destructive: dropping the mask must break the explicit-false
proof; materializing IPv4, false, or GR defaults must break exact TOML absence;
bypassing raw intent in PeerManager must break live inheritance; bypassing it
in `ConfigEvent` must break persistence/restart parity; changing legacy
conversion must break legacy characterization; and adding client fallback must
break the old-server fail-closed proof.

## Consequences

Runtime-created group members can use the same inheritance resolver as
file-created members without changing legacy requests. Disk and actor-owned
snapshots retain operator intent rather than a resolved projection, so restart
does not change effective behavior.

The cost is a server-first rollout and an internal carrier threaded through two
owners. The same RPC supports both contracts, but clients must treat the
payload choice as a semantic version boundary. Some explicit-clear operations
remain unavailable until the underlying config representation becomes
tri-state.

## Exclusions and documentation fence

This decision does not implement:

- a new service, package, or v2 RPC;
- a `oneof` migration for the legacy field;
- automatic legacy fallback;
- a broad peer-group or tri-state config redesign;
- one-off fixes for individual route-server or route-reflector flags.

The API/configuration docs and v1 stable-surface digest describe the reviewed
additive graph. CLI help, completions, and examples describe the shipped
presence-aware client; ROADMAP state is intentionally unchanged.
