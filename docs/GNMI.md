# gNMI / OpenConfig Telemetry

rustbgpd exposes a read-only `gnmi.gNMI` service for a strict OpenConfig BGP
operational-state subset. It is intended for collectors and tools such as
`gnmic` that already speak gNMI/OpenConfig.

This is not a full OpenConfig router model. The v1 surface is deliberately
narrow: `Capabilities`, `Get`, and `Subscribe` for BGP global and neighbor
state. `Set` is present because gNMI defines it, but always returns
`UNIMPLEMENTED` after authorization.

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
are `sensitive_read`; `Set` is `operator_only` even though it is unimplemented.

## Supported RPCs

| RPC | Status |
|-----|--------|
| `Capabilities` | Returns gNMI version `0.10.0`, the OpenConfig modules backing the supported paths, and `JSON` / `JSON_IETF` encodings. |
| `Get` | Returns the supported OpenConfig BGP global and neighbor `state` subset. |
| `Subscribe` | Supports `ONCE`, `POLL`, `STREAM SAMPLE`, and `STREAM ON_CHANGE` (the last is scoped to the neighbor session-state leaf — see below). |
| `Set` | Returns `UNIMPLEMENTED` for an authorized operator-tier principal. Lower-tier callers receive `PERMISSION_DENIED` before the handler runs. |

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
above one hour is capped at the 1-hour ceiling.

## Troubleshooting

| Symptom | Likely cause |
|---------|--------------|
| `gnmi.gNMI` is missing on a TCP listener | The listener is plaintext or bearer-token-only. Configure native mTLS with `tls_cert_file`, `tls_key_file`, and `tls_client_ca_file`. |
| `PERMISSION_DENIED` | The method exceeds the listener `max_tier`, the mTLS principal is not mapped in `[security.grpc.roles]`, or the mapped role is below the method tier. |
| `UNIMPLEMENTED` for a path | The path is valid OpenConfig but outside rustbgpd's supported whitelist. This is expected for per-AFI counters, negotiated capabilities, `last-established`, and unsupported subtrees. |
| `INVALID_ARGUMENT` | The path is malformed, uses unsupported key syntax, or omits required keys such as `network-instance`, `protocol`, or `neighbor-address`. |
| `NOT_FOUND` | The requested keyed object does not exist, such as a neighbor address that is not configured. |
| `Set` returns `UNIMPLEMENTED` | Expected for an authorized operator-tier principal. gNMI mutation is deferred until rustbgpd has a daemon-wide config transaction model. |

## Interop Proof

M54 validates this surface with the real `gnmic` client over mTLS:

```bash
bash tests/interop/scripts/gen-m54-certs.sh
containerlab deploy -t tests/interop/m54-gnmi-openconfig.clab.yml
bash tests/interop/scripts/test-m54-gnmi-openconfig.sh
containerlab destroy -t tests/interop/m54-gnmi-openconfig.clab.yml --cleanup
```
