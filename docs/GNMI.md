# gNMI / OpenConfig Telemetry

rustbgpd exposes `gnmi.gNMI` for a strict OpenConfig BGP operational-state
subset. It is intended for collectors and tools such as `gnmic` that already
speak gNMI/OpenConfig.

This is not a full OpenConfig router model. The v1 surface is deliberately
narrow: `Capabilities`, `Get`, and `Subscribe` for BGP global and neighbor
state, plus a small `Set` subset for durable static BGP neighbor, peer-group,
and dynamic-neighbor-prefix config. `Set` maps supported OpenConfig mutations onto the ADR-0076 transaction model:
payloads are redacted in audit logs, delete / replace / update operations are
normalized into gNMI application order, and successful mutations build full
candidate TOML before using the same plan/apply/persist/rollback path as native
config transactions.

Design details live in [ADR-0070](adr/0070-gnmi-openconfig-telemetry.md). The
complete native gRPC reference remains [API.md](API.md).

## Listener Setup

Network gNMI is registered only on TCP listeners with native mTLS enabled. A
plaintext or bearer-token-only TCP listener serves the native `rustbgpd.v1` API
but does not register `gnmi.gNMI`.

The local Unix socket may also expose `gnmi.gNMI` as a same-host convenience for
co-located collectors. That UDS path is a rustbgpd extension, not
standards-compliant network gNMI.

Minimal TCP listener:

```toml
[global.telemetry.grpc_tcp]
address = "0.0.0.0:50051"
tls_cert_file = "/etc/rustbgpd/certs/server.pem"
tls_key_file = "/etc/rustbgpd/certs/server.key"
tls_client_ca_file = "/etc/rustbgpd/certs/ca.pem"

[security.grpc.roles]
"rustbgpd://observer/collector" = "observer"
```

`[security.grpc].enforcement = "tier"` is the default. For mTLS listeners, the
principal is derived from the verified client certificate in ADR-0064 order:
`rustbgpd:` URI SAN, then email SAN, then Subject CN. The principal must have a
matching `[security.grpc.roles]` entry. `Capabilities`, `Get`, and `Subscribe`
are `sensitive_read`; `Set` is `operator_only`.

## Supported RPCs

| RPC | Status |
|-----|--------|
| `Capabilities` | Returns gNMI version `0.10.0`, the OpenConfig modules backing the supported paths, and `JSON` / `JSON_IETF` encodings. |
| `Get` | Returns the supported OpenConfig BGP global and neighbor `state` subset. |
| `Subscribe` | Supports `ONCE`, `POLL`, `STREAM SAMPLE`, and `STREAM ON_CHANGE` (the last is scoped to the neighbor session-state leaf — see below). |
| `Set` | Operator-only. Supports the static-neighbor and peer-group config subsets below through ADR-0076 transactions; unsupported paths return `UNIMPLEMENTED`, malformed values return `INVALID_ARGUMENT`, and transaction precondition failures return `FAILED_PRECONDITION`. Lower-tier callers receive `PERMISSION_DENIED` before the handler runs. |

### `Set` static-neighbor scope

The first supported config surface is static, numbered BGP neighbors under:

```text
/network-instances/network-instance[name=DEFAULT]/protocols/protocol[identifier=BGP][name=BGP]/bgp/neighbors/neighbor[neighbor-address=X]/config
```

Supported operations:

- `update` / `replace` the leaf values `neighbor-address`, `peer-as`,
  `description`, and `peer-group`.
- `update` / `replace` `.../graceful-restart/config/enabled`,
  `.../graceful-restart/config/restart-time`, and
  `.../graceful-restart/config/stale-routes-time`, mapped to native
  `graceful_restart`, `gr_restart_time`, and `gr_stale_routes_time`.
  `stale-routes-time` accepts whole seconds only; fractional decimal64
  values are rejected, never rounded. `config/helper-only` returns
  `UNIMPLEMENTED` — rustbgpd GR helper behavior is not a per-session knob.
- Create a new static neighbor by setting `peer-as` under a concrete
  `neighbor[neighbor-address=X]` entry. The list key supplies the durable
  `[[neighbors]].address`; if `config/neighbor-address` is also supplied, it
  must match the key.
- Delete a whole static neighbor list entry by deleting
  `.../neighbors/neighbor[neighbor-address=X]`. Per gNMI, deleting a missing
  entry is silently accepted.

Transaction and validation behavior:

- Set payloads are summarized as operation counts only; values are redacted
  before `grpc_authz` audit logging because future OpenConfig config leaves can
  carry credentials.
- `delete`, `replace`, and `update` are prefix-expanded and forwarded in the
  gNMI-specified application order: all deletes, then replaces, then updates.
- `replace` and `update` require `TypedValue`; the deprecated `Value` field is
  rejected with `INVALID_ARGUMENT`.
- non-empty `union_replace` returns `UNIMPLEMENTED` until dedicated support
  ships.
- the standard gNMI commit-confirmed extension is supported for `commit`,
  `confirm`, `cancel`, and `set_rollback_duration` actions. Unsupported
  extension types return `UNIMPLEMENTED`.
- supported changes translate the live runtime config snapshot into candidate
  TOML and call the ADR-0076 transaction controller. There is no parallel commit
  path.
- If either the running or generated candidate references external `.rpol`
  graphs or `[policy.datasets]` snapshots, a supported non-noop Set is rejected
  before mutation: those bytes are outside the transaction token and rollback
  boundary. A true no-op remains a no-op. Deploy the TOML and external files
  together and use SIGHUP. (The native transaction API's targeted pure-
  `[[fib_tables]]` exception is not a gNMI Set surface.)
- unsupported config leaves, including `enabled`, `local-as`, auth, timers,
  transport, BFD, AFI-SAFI, policy, route-reflector/client,
  route-server-client, and Add-Path settings, return `UNIMPLEMENTED`.
- IPv6 link-local / BGP unnumbered neighbor Set is deferred because OpenConfig's
  `neighbor-address` key does not carry the interface identity rustbgpd needs to
  identify those peers safely.
- `peer-group` references must name an existing rustbgpd peer group.
- Create a peer group in its own Set transaction before referencing it from a
  new neighbor. ADR-0076 still rejects mixed-family candidates such as
  "create peer group and add neighbor" in one Set when the combined diff cannot
  be classified as one supported transaction family.

### `Set` peer-group scope

The supported peer-group config surface is under:

```text
/network-instances/network-instance[name=DEFAULT]/protocols/protocol[identifier=BGP][name=BGP]/bgp/peer-groups/peer-group[peer-group-name=NAME]
```

Supported operations:

- `update` / `replace` `.../config/peer-group-name`. The value must match the
  `peer-group[peer-group-name=NAME]` key; setting it creates an empty native
  `[peer_groups.NAME]` entry when one does not already exist.
- `update` / `replace` `.../config/auth-password`, mapped to native
  `md5_password`.
- `update` / `replace` `.../config/remove-private-as`, mapped to native
  `remove_private_as`. The bridge accepts rustbgpd's native values
  (`remove`, `all`, `replace`) and common OpenConfig identity spellings such as
  `PRIVATE_AS_REMOVE_ALL`.
- `update` / `replace` `.../timers/config/hold-time`, mapped to native
  `hold_time`.
- `update` / `replace` `.../graceful-restart/config/enabled`,
  `.../graceful-restart/config/restart-time`, and
  `.../graceful-restart/config/stale-routes-time`, mapped to the native
  inherited `graceful_restart`, `gr_restart_time`, and
  `gr_stale_routes_time` group keys, with the same value rules as the
  static-neighbor graceful-restart scope above.
- Delete a whole peer-group list entry by deleting
  `.../peer-groups/peer-group[peer-group-name=NAME]`. Per gNMI, deleting a
  missing entry is silently accepted.

Transaction and validation behavior:

- Peer-group Set changes use the same candidate-TOML transaction path as native
  config changes. Unused peer-group catalog edits commit as catalog-only
  transactions; edits that affect live sessions use ADR-0076's
  peer-group/session reshape executor — static members are reconfigured in
  place, and live dynamic sessions accepted by an affected range are
  gracefully reset after persist to re-accept under the committed config
  (ADR-0086).
- The external-policy-input fence above applies even when the requested
  peer-group leaf itself is unrelated to policy; the executor would otherwise
  adopt the whole generated candidate snapshot.
- If a candidate peer-group edit would affect a dynamic-neighbor range in a
  way that the transaction model cannot safely reshape (for example a range
  peer-group reassignment, or mixed policy/session impact), the transaction
  is rejected by the native planner rather than silently drifting.
- OpenConfig peer-group leaves without a native inherited config model remain
  unsupported, including `config/peer-as`, `config/local-as`,
  `config/peer-type`, `config/send-community-type`, and `config/description`.

### `Set` dynamic-neighbor-prefix scope

The supported dynamic-neighbor-prefix surface is under:

```text
/network-instances/network-instance[name=DEFAULT]/protocols/protocol[identifier=BGP][name=BGP]/bgp/global/dynamic-neighbor-prefixes/dynamic-neighbor-prefix[prefix=P]
```

Supported operations:

- `update` / `replace` `.../config/prefix`. The value must match the
  `dynamic-neighbor-prefix[prefix=P]` key.
- `update` / `replace` `.../config/peer-group`, referencing an existing native
  peer group.
- Delete a whole dynamic-neighbor-prefix list entry by deleting
  `.../dynamic-neighbor-prefix[prefix=P]`. Per gNMI, deleting a missing entry
  is silently accepted.

Transaction and validation behavior:

- OpenConfig dynamic ranges expose `prefix` and `peer-group` only. rustbgpd maps
  an OpenConfig-created range to native `[[dynamic_neighbors]]` with
  `remote_asn = 0` (accept any ASN from the peer's OPEN) and no description.
- Native config validation still applies: `peer-group` must exist, exact
  duplicate effective prefixes are rejected, IPv4/IPv6 prefix lengths are
  bounded, overlapping different-length ranges are allowed, and BFD-enabled
  peer groups are rejected for dynamic ranges.
- Dynamic range changes use the existing `[[dynamic_neighbors]]` full-set
  transaction family. Creating a peer group and dynamic range in the same Set
  may still be rejected as a mixed-family candidate; create the peer group
  first, then apply the dynamic range.
- Dynamic-neighbor state paths and native-only fields such as range
  `description` or explicit `remote_asn` are not supported by OpenConfig Set.

### `Set` commit-confirmed workflow

The gNMI `Commit` extension maps onto the same ADR-0076 commit-confirmed
controller used by `rbgp config apply --confirm-id`:

- `CommitRequest` starts a confirmed Set. It must include normal Set operations
  and a non-empty `id`; the optional `rollback_duration` maps to the native
  confirm timeout. If omitted, the native default timeout is used.
- `CommitConfirm` confirms a pending transaction. It must carry only the
  extension, with no delete / replace / update operations.
- `CommitCancel` aborts and rolls back a pending transaction. It must also carry
  only the extension.
- `CommitSetRollbackDuration` resets the rollback timer for the pending
  transaction. Its `id` must match the pending transaction, it must include a
  positive whole-second `rollback_duration`, and it overwrites the current timer
  rather than appending time.

Only one confirmed transaction may be pending at a time. While pending, normal
Set mutations return `FAILED_PRECONDITION` until the transaction is confirmed,
canceled, or auto-reverted.

### `STREAM ON_CHANGE` v1 scope

`STREAM ON_CHANGE` covers the
`…/neighbor[neighbor-address=*]/state/session-state` leaf only.
Both the explicit `*` wildcard (the form gnmic and most OpenConfig
collectors emit) and the no-key shorthand `…/neighbor/state/session-state`
lower to "all configured neighbors"; a concrete address is also
accepted.

- **EHM required.** `Subscribe ON_CHANGE` sources transitions from the
  durable event broadcast (ADR-0072). When `[event_history]` is
  disabled or EHM is in pass-through, the RPC returns
  `FAILED_PRECONDITION` immediately on subscribe.
- **Initial sync.** The handler emits one OpenConfig leaf `Update`
  per configured peer (including non-Established peers — `IDLE` /
  `CONNECT` / `ACTIVE` / `OPENSENT` / `OPENCONFIRM` / `ESTABLISHED`)
  followed by `sync_response`.
- **Live stream.** For every FSM transition committed to EHM under
  `EVENT_CATEGORY_SESSION`, the handler emits a single
  `session-state` leaf `Update` with the new short-form state.
- **Reconnect.** gNMI carries no cursor on reconnect, so a fresh
  subscription gets a fresh initial snapshot — the disconnect
  window is **not** replayed. Collectors that need historical
  replay use `EventService.SubscribeFromEvent` directly.
- **Unsupported leaves.** Any other path under `ON_CHANGE` returns
  `UNIMPLEMENTED` with a message naming the supported leaf. The
  counter leaves (`messages/*`) and the `enabled` leaf stay
  SAMPLE/POLL-only in v1.
- **Lag.** When the EHM broadcast receiver falls behind, the stream
  closes with `DATA_LOSS` so the collector reconnects and resyncs
  from a fresh initial snapshot. `Subscribe ON_CHANGE` does not
  paper over gaps.
- **Mixed-mode subscriptions.** A `SubscriptionList` that mixes
  `SAMPLE` and `ON_CHANGE` subscriptions is rejected with
  `UNIMPLEMENTED` — the v1 dispatch picks one mode per stream.

Broad subtree requests are bounded; v1 does not use gNMI to stream
the full route table.

A concrete keyed-neighbor subscription whose successful peer snapshot does not
contain that neighbor emits no update for the cycle; sync still completes and
POLL/STREAM remain live for later appearances. Concrete neighbor `Get` remains
strictly `NOT_FOUND`, and peer-snapshot failures remain `UNAVAILABLE`.

## Dial-out (device-initiated push)

Everything above is dial-in: a collector connects to the daemon. The
`[gnmi_dialout]` config section inverts only the transport direction —
the daemon opens a persistent gRPC connection to each configured
collector and pushes the exact `SubscribeResponse` stream the dial-in
`Subscribe` server would produce for the same subscription (initial
snapshot, `sync_response`, then SAMPLE ticks or ON_CHANGE events; same
supported paths, same ON_CHANGE scope, same validation). This is the
ingestion model large fleets use: devices behind NAT push to a central
sink instead of every collector dialing every device.

The wire contract is `rustbgpd.gnmi_dialout.v1.GnmiDialout/Publish`
(`proto/rustbgpd_dialout.proto`): the device is the gRPC client and
sends `stream gnmi.SubscribeResponse`; the collector's response stream
is reserved for future flow control and may stay silent. This mirrors
the de-facto vendor dial-out shape without impersonating any vendor
namespace; a collector implements one trivially by serving that proto.
The OpenConfig grpc-tunnel model solves the same reachability inversion
at the transport layer and remains a possible future alternative.

Subscriptions are declared in config (paths + `sample`/`on_change` mode
per target), TLS uses the standard `tls_ca_file`/`tls_cert_file`/
`tls_key_file` path idiom, reconnects use capped exponential backoff,
and connection state is exported as `gnmi_dialout_connected{target}`.
Full field reference: `docs/CONFIGURATION.md` `[gnmi_dialout]`;
operational behavior: `docs/OPERATIONS.md`.

## Supported Paths

All paths hang under the default network instance and BGP protocol:

```text
/network-instances/network-instance[name=DEFAULT]/protocols/protocol[identifier=BGP][name=BGP]/bgp
```

The default network-instance key is `DEFAULT`. The BGP protocol identifier uses
the bare identity value `BGP`, not `oc-pol-types:BGP`. The protocol name is the
operator-assigned instance name; `BGP` is the normal rustbgpd value.

Supported global state:

```text
/network-instances/network-instance[name=DEFAULT]/protocols/protocol[identifier=BGP][name=BGP]/bgp/global/state
/network-instances/network-instance[name=DEFAULT]/protocols/protocol[identifier=BGP][name=BGP]/bgp/global/state/as
/network-instances/network-instance[name=DEFAULT]/protocols/protocol[identifier=BGP][name=BGP]/bgp/global/state/router-id
```

Supported neighbor state:

```text
/network-instances/network-instance[name=DEFAULT]/protocols/protocol[identifier=BGP][name=BGP]/bgp/neighbors/neighbor[neighbor-address=X]/state
/network-instances/network-instance[name=DEFAULT]/protocols/protocol[identifier=BGP][name=BGP]/bgp/neighbors/neighbor[neighbor-address=X]/state/neighbor-address
/network-instances/network-instance[name=DEFAULT]/protocols/protocol[identifier=BGP][name=BGP]/bgp/neighbors/neighbor[neighbor-address=X]/state/enabled
/network-instances/network-instance[name=DEFAULT]/protocols/protocol[identifier=BGP][name=BGP]/bgp/neighbors/neighbor[neighbor-address=X]/state/peer-as
/network-instances/network-instance[name=DEFAULT]/protocols/protocol[identifier=BGP][name=BGP]/bgp/neighbors/neighbor[neighbor-address=X]/state/local-as
/network-instances/network-instance[name=DEFAULT]/protocols/protocol[identifier=BGP][name=BGP]/bgp/neighbors/neighbor[neighbor-address=X]/state/session-state
/network-instances/network-instance[name=DEFAULT]/protocols/protocol[identifier=BGP][name=BGP]/bgp/neighbors/neighbor[neighbor-address=X]/state/established-transitions
/network-instances/network-instance[name=DEFAULT]/protocols/protocol[identifier=BGP][name=BGP]/bgp/neighbors/neighbor[neighbor-address=X]/state/messages
```

For scoped IPv6 link-local neighbors, the OpenConfig `neighbor-address` key is
the bare IP address, not `fe80::x%ifname`. rustbgpd v1 rejects configuring the
same link-local neighbor address on multiple interfaces, so the bare key remains
unambiguous.

## gnmic Examples

Set these once for the examples:

```bash
export RUSTBGPD_GNMI_ADDR=rustbgpd.example.net:50051
export RUSTBGPD_TLS_CA=/etc/rustbgpd/certs/ca.pem
export RUSTBGPD_TLS_CERT=/etc/operator/collector.pem
export RUSTBGPD_TLS_KEY=/etc/operator/collector.key
export RUSTBGPD_TLS_SERVER_NAME=rustbgpd.example.net
export OC_BGP='/network-instances/network-instance[name=DEFAULT]/protocols/protocol[identifier=BGP][name=BGP]/bgp'
```

Capabilities:

```bash
gnmic \
  --address "$RUSTBGPD_GNMI_ADDR" \
  --tls-ca "$RUSTBGPD_TLS_CA" \
  --tls-cert "$RUSTBGPD_TLS_CERT" \
  --tls-key "$RUSTBGPD_TLS_KEY" \
  --tls-server-name "$RUSTBGPD_TLS_SERVER_NAME" \
  capabilities
```

Global state:

```bash
gnmic \
  --address "$RUSTBGPD_GNMI_ADDR" \
  --tls-ca "$RUSTBGPD_TLS_CA" \
  --tls-cert "$RUSTBGPD_TLS_CERT" \
  --tls-key "$RUSTBGPD_TLS_KEY" \
  --tls-server-name "$RUSTBGPD_TLS_SERVER_NAME" \
  get \
  --encoding json_ietf \
  --type STATE \
  --path "$OC_BGP/global/state"
```

One neighbor:

```bash
gnmic \
  --address "$RUSTBGPD_GNMI_ADDR" \
  --tls-ca "$RUSTBGPD_TLS_CA" \
  --tls-cert "$RUSTBGPD_TLS_CERT" \
  --tls-key "$RUSTBGPD_TLS_KEY" \
  --tls-server-name "$RUSTBGPD_TLS_SERVER_NAME" \
  get \
  --encoding json_ietf \
  --type STATE \
  --path "$OC_BGP/neighbors/neighbor[neighbor-address=10.0.0.2]/state"
```

Add and delete a static numbered neighbor:

```bash
gnmic \
  --address "$RUSTBGPD_GNMI_ADDR" \
  --tls-ca "$RUSTBGPD_TLS_CA" \
  --tls-cert "$RUSTBGPD_TLS_CERT" \
  --tls-key "$RUSTBGPD_TLS_KEY" \
  --tls-server-name "$RUSTBGPD_TLS_SERVER_NAME" \
  set \
  --update "$OC_BGP/neighbors/neighbor[neighbor-address=10.0.0.3]/config/peer-as:::uint:::65003"

gnmic \
  --address "$RUSTBGPD_GNMI_ADDR" \
  --tls-ca "$RUSTBGPD_TLS_CA" \
  --tls-cert "$RUSTBGPD_TLS_CERT" \
  --tls-key "$RUSTBGPD_TLS_KEY" \
  --tls-server-name "$RUSTBGPD_TLS_SERVER_NAME" \
  set \
  --delete "$OC_BGP/neighbors/neighbor[neighbor-address=10.0.0.3]"
```

Commit-confirmed Set:

```bash
gnmic \
  --address "$RUSTBGPD_GNMI_ADDR" \
  --tls-ca "$RUSTBGPD_TLS_CA" \
  --tls-cert "$RUSTBGPD_TLS_CERT" \
  --tls-key "$RUSTBGPD_TLS_KEY" \
  --tls-server-name "$RUSTBGPD_TLS_SERVER_NAME" \
  set \
  --commit-id deploy-42 \
  --commit-request \
  --rollback-duration 120s \
  --update "$OC_BGP/neighbors/neighbor[neighbor-address=10.0.0.4]/config/peer-as:::uint:::65004"

gnmic \
  --address "$RUSTBGPD_GNMI_ADDR" \
  --tls-ca "$RUSTBGPD_TLS_CA" \
  --tls-cert "$RUSTBGPD_TLS_CERT" \
  --tls-key "$RUSTBGPD_TLS_KEY" \
  --tls-server-name "$RUSTBGPD_TLS_SERVER_NAME" \
  set \
  --commit-id deploy-42 \
  --commit-confirm
```

To abort the pending change before the timeout, use `--commit-cancel` with the
same `--commit-id`.

Sampled stream:

```bash
gnmic \
  --address "$RUSTBGPD_GNMI_ADDR" \
  --tls-ca "$RUSTBGPD_TLS_CA" \
  --tls-cert "$RUSTBGPD_TLS_CERT" \
  --tls-key "$RUSTBGPD_TLS_KEY" \
  --tls-server-name "$RUSTBGPD_TLS_SERVER_NAME" \
  subscribe \
  --encoding json_ietf \
  --mode stream \
  --stream-mode sample \
  --sample-interval 10s \
  --path "$OC_BGP/global/state/router-id"
```

The requested `--sample-interval` is clamped to `[1s, 1h]`: a sub-second
or zero/missing interval is raised to the 1-second floor, and anything
above one hour is capped at the 1-hour ceiling. Multiple SAMPLE paths in one
subscription retain their own clamped intervals; co-due neighbor paths share
one peer snapshot, and delayed ticks skip missed periods without catch-up bursts.

## Troubleshooting

| Symptom | Likely cause |
|---------|--------------|
| `gnmi.gNMI` is missing on a TCP listener | The listener is plaintext or bearer-token-only. Configure native mTLS with `tls_cert_file`, `tls_key_file`, and `tls_client_ca_file`. |
| `PERMISSION_DENIED` | The method exceeds the listener `max_tier`, the mTLS principal is not mapped in `[security.grpc.roles]`, or the mapped role is below the method tier. |
| `UNIMPLEMENTED` for a path | The path is valid OpenConfig but outside rustbgpd's supported whitelist. This is expected for per-AFI counters, negotiated capabilities, `last-established`, and unsupported subtrees. |
| `INVALID_ARGUMENT` | The path is malformed, uses unsupported key syntax, or omits required keys such as `network-instance`, `protocol`, or `neighbor-address`. |
| `NOT_FOUND` | The requested keyed object does not exist, such as a neighbor address that is not configured. |
| `Set` returns `UNIMPLEMENTED` | The path or extension is outside the supported Set subset, such as unsupported neighbor leaves, `union_replace`, or a non-Commit extension. |

## Interop Proof

M54 validates this surface with the real `gnmic` client over mTLS, including
Capabilities, Get, Set add/delete, commit-confirmed Set confirm/cancel,
read-tier Set denial, unsupported-path rejection, and Subscribe SAMPLE:

```bash
bash tests/interop/scripts/gen-m54-certs.sh
containerlab deploy -t tests/interop/m54-gnmi-openconfig.clab.yml
bash tests/interop/scripts/test-m54-gnmi-openconfig.sh
containerlab destroy -t tests/interop/m54-gnmi-openconfig.clab.yml --cleanup
```
