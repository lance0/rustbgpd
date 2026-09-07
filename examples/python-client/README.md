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

Native mTLS accepts TLS 1.2 and TLS 1.3 with the rustls/ring default cipher
suites; protocol versions and cipher suites have no configuration overrides.
A trusted certificate can complete TLS even without a mapped principal, but
its RPCs then receive `PERMISSION_DENIED` from role authorization.

After staging replacement files at the configured paths, run on the daemon
host before SIGHUP or restart:

```bash
rustbgpd --check --strict /etc/rustbgpd/config.toml
```

Both check modes parse the server certificate, private key, and client CA
bundle and check the cert/key match through startup credential staging,
without binding listeners. This checks the files at that moment; it does not
prove client trust or hostname matching, or cover later file changes.

Rejected TLS handshakes happen before RPC authorization. Monitor
`bgp_grpc_tls_handshake_failures_total{reason}` for certificate rejections and
handshake timeouts; these failures do not increment
`bgp_grpc_authz_decisions_total`. The [operations reference](../../docs/reference/operations.md)
lists the fixed reasons. TLS alert delivery to the client is best effort, so
use the server metric when a client reports only a connection failure.

For expiry warnings, set `tls_expiry_warning_seconds = 604800` on the daemon's
TCP listener and restart it. The default `0` disables warnings; active
certificate expiry metrics and successful-client leaf metadata logs remain
available. `--check` reports configured warnings with exit 0, while
`--check --strict` returns 1. Successful client-handshake logs describe observed
clients only; the daemon does not maintain a client certificate inventory.
See [native gRPC certificate expiry](../../docs/reference/operations.md#native-grpc-certificate-expiry)
for the active-generation gauges and the limits of supplied bundle minima.

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

Supply `--tls-cert` and `--tls-key` together with `--tls-ca`; incomplete
combinations fail before credentials are read or a channel is created.
`--tls-ca` alone enables server-authenticated TLS without a client certificate.

The controller preserves the first unary RPC error and exits nonzero, without
automatic cleanup or retries. A deadline or transport failure can occur after
the daemon has applied an injection or withdrawal: inspect the route state
before deciding how to recover. Exit 0 means the unary calls succeeded; the
watcher starts concurrently and may miss immediate events, and stream errors
are printed without changing that exit status.

After installing the dependencies and generating the stubs, run the connection
checks from this directory with `python -m unittest -v test_connect`.

## The UDS trap

Both scripts also accept a `unix:///var/lib/rustbgpd/grpc.sock` target. With
the daemon's default owner-only listener, a same-user client needs no
credentials at all. That result is misleading, and it is the single easiest
way to ship a controller that has never been authorization-tested.

Under tier enforcement an owner-only UDS socket — no group or world mode bits,
which is the default `0o600`, including the implicit default listener — with
no configured `principal` authorizes its clients as the reserved implicit
`local-operator` principal **at operator tier**, with no
`[security.grpc.roles]` entry required and none consulted. Without a
`token_file`, audit records label this permissions-only path
`authn = "uds_owner"`. A configured `token_file` requires its bearer token in
addition to filesystem access and reports `authn = "bearer_token"`; the
listener's principal and role ceiling stay the same. An explicit UDS principal
without a token reports `authn = "uds"`.

Keep mode `0o600` for ordinary local access. Deliberately shared sockets still
require an explicit `principal` plus a matching role entry: every client
admitted by filesystem permissions receives that listener-wide role. A bearer
token is optional and does not provide per-user roles.

The socket path must be absolute and contain no symlinks or `..` components.
The daemon validates its ancestors and requires an effective-UID-owned
immediate parent with no group/world write bits, so a socket directly in
`/tmp` is rejected — use a private daemon-owned directory beneath it. Missing
parents are created with mode `0700`, so deliberate group access also needs a
pre-created, group-searchable parent with the intended socket group. See
[Unix socket path integrity](../../docs/reference/security.md#unix-socket-path-integrity)
and the [setgid parent recipe](../../docs/reference/configuration.md#globaltelemetrygrpc_uds)
for the complete path rules and shared-access setup.

So a script run against that default local socket exercises the full gRPC surface,
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
