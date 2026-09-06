# Python gRPC client example

Two worked scripts that drive a running rustbgpd from Python over the native
`rustbgpd.v1` gRPC API.

This is an example, not a package: there is nothing to install beyond the two
pinned dependencies, and nothing here is part of the build.

## When this beats shelling out to `rbgp`

`rbgp -j watch` already emits NDJSON with reconnection and backoff, so for
tailing events on a host that has the binary, `subprocess.Popen` around `rbgp`
is less code and more robust than a hand-rolled gRPC loop. Reach for a Python
client when **there is no `rbgp` binary on the host** — a containerized
controller or sidecar that talks mTLS from its own identity, gets typed
protobuf messages instead of parsed JSON, and sets its own per-call deadline
on every RPC. Both scripts here pass an explicit `timeout=` to every call for
exactly that reason.

## Generate the stubs

From the repository root, with `grpcio-tools` installed:

```bash
python -m grpc_tools.protoc -I proto \
  --python_out=examples/python-client --grpc_python_out=examples/python-client \
  proto/rustbgpd.proto
```

The generated `rustbgpd_pb2.py` / `rustbgpd_pb2_grpc.py` are deliberately
**not** committed — a vendored copy goes stale against `proto/rustbgpd.proto`
with nothing to catch it — so `.gitignore` covers them. Regenerate after every
proto change. Run the scripts from this directory so the generated modules are
importable.

```bash
python -m pip install -r requirements.txt
```

## Deployment shape: mTLS TCP

This is the shape to build against. A TCP listener under the default tier
authorization must authenticate, and mTLS is the recommended default for any
non-loopback gRPC listener:

```toml
[global.telemetry.grpc_tcp]
address = "0.0.0.0:50051"
token_file = "/etc/rustbgpd/grpc.token"
tls_cert_file = "/etc/rustbgpd/server.pem"
tls_key_file = "/etc/rustbgpd/server.key"
tls_client_ca_file = "/etc/rustbgpd/client-ca.pem"

[security.grpc]
enforcement = "tier"

[security.grpc.roles]
"rustbgpd://operator/python-example" = "operator"
```

The daemon derives the principal from the client certificate (URI SAN, then
email SAN, then Subject CN) and looks it up in `[security.grpc.roles]`. A
`rustbgpd://` URI SAN keeps the principal string explicit and greppable.

```bash
python explain.py \
  --target rustbgpd.example.net:50051 \
  --tls-ca /etc/controller/server-ca.pem \
  --tls-cert /etc/controller/client.pem \
  --tls-key /etc/controller/client.key \
  --token-file /etc/controller/grpc.token \
  --peer 192.0.2.2 --prefix 198.51.100.0/24
```

```bash
python controller.py \
  --target rustbgpd.example.net:50051 \
  --tls-ca /etc/controller/server-ca.pem \
  --tls-cert /etc/controller/client.pem \
  --tls-key /etc/controller/client.key \
  --token-file /etc/controller/grpc.token \
  --prefix 198.51.100.0/24 --next-hop 192.0.2.1
```

The bearer token is attached with `grpc.metadata_call_credentials` composed
into the channel credentials via `grpc.composite_channel_credentials`, never
as per-call `metadata=`. The credential then lives on the channel, so no call
site can forget it and no traceback or log line carries it. gRPC only ships
call credentials over a channel with transport security, which is why a token
requires mTLS (or, on loopback and Unix sockets,
`grpc.local_channel_credentials`).

`controller.py` reuses `add_connection_arguments`, `connect`, and
`parse_prefix` from `explain.py` rather than restating them.

## The UDS trap

Both scripts also accept a `unix:///var/lib/rustbgpd/grpc.sock` target, and on
a development box everything will work immediately with no credentials at all.
That result is misleading, and it is the single easiest way to ship a
controller that has never been authorization-tested.

Under tier enforcement an owner-only UDS socket — no group or world mode bits,
which is the default `0o600`, including the implicit default listener — is
authenticated by its own filesystem permissions. Its clients are authorized as
the reserved implicit `local-operator` principal **at operator tier**, with no
`[security.grpc.roles]` entry required and none consulted. Audit records label
that path `authn = "uds_owner"`. Group- or world-accessible sockets are
different: they still require an explicit `principal` plus a matching role
entry.

So a script run against a local socket exercises the full gRPC surface,
including every `operator_only` RPC, and proves nothing about whether the
identity it will use in production is allowed to call them. Test the
authorization tiers on the listener you will actually deploy against. See the
"Current gaps" section of
[`docs/reference/security.md`](../../docs/reference/security.md) for the full
statement.

One further Unix-socket detail: gRPC defaults the HTTP/2 `:authority` header
to the socket path, which the daemon's HTTP/2 stack rejects as malformed. Both
scripts set `grpc.default_authority` for `unix:` targets; any valid host token
works, since it is never used for routing on a Unix socket.

## Authorization tiers

`docs/reference/grpc-method-inventory.json` is the machine-readable tier
source, generated from `crates/api/src/authz.rs`. Roles cap the tier a
principal may reach: Observer stops at `sensitive_read`, Automation at
`mutating`, Operator covers the whole surface.

| Script | RPCs | Tier | Minimum role |
|---|---|---|---|
| `explain.py` | `RibService.ExplainAdvertisedRoute` | `sensitive_read` | Observer |
| `controller.py` | `ControlService.GetHealth`, `EventService.WatchEvents` | `sensitive_read` | Observer |
| `controller.py` | `InjectionService.AddPath`, `InjectionService.DeletePath` | `operator_only` | Operator |

Route injection is `operator_only`, not `mutating`, so `controller.py` needs an
Operator principal. Split the two halves across two principals if the health
and event polling should not carry injection rights.

## Stability

Every RPC called here appears in `stable_method_sets` in
[`docs/reference/v1-stable-surface.json`](../../docs/reference/v1-stable-surface.json),
which hash-pins each service's `signature_sha256` and `message_graph_sha256`;
a rename anywhere in a message graph these scripts depend on fails
`scripts/check-v1-stable-surface.py` before it can silently break them.
