# Envoy mTLS Frontend for rustbgpd

This example shows an Envoy-fronted remote-management posture for rustbgpd:

- keep rustbgpd itself on loopback (or a local Unix domain socket when your
  deployment exposes one)
- terminate mutual TLS in Envoy
- expose only Envoy's frontend port to remote operators

rustbgpd also supports native gRPC mTLS on its TCP listener
(`tls_cert_file`, `tls_key_file`, and `tls_client_ca_file`). Use that direct
path when one daemon can own certificate validation itself. Keep this Envoy
pattern when you want a shared proxy layer, central certificate rotation,
extra HTTP/2 controls, or one frontend policy for multiple local daemons.

The included [`envoy.yaml`](envoy.yaml) proxies gRPC over HTTP/2 from
`0.0.0.0:50052` to a local rustbgpd backend on `/var/lib/rustbgpd/grpc.sock`.

## Backend rustbgpd config

Keep the daemon on a local-only listener. No extra gRPC config is
required if you keep the default UDS:

```toml
[global]
runtime_state_dir = "/var/lib/rustbgpd"

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"
```

A loopback TCP backend is also possible, but it must carry its own
credential: `security.grpc.enforcement = "tier"` is the only enforcement
mode, and an unauthenticated TCP listener is rejected at config load. Use a
bearer token (Envoy then has to inject the header itself):

```toml
[global.telemetry.grpc_tcp]
address = "127.0.0.1:50051"
token_file = "/etc/rustbgpd/grpc.token"
principal = "envoy-frontend"

[security.grpc.roles]
"envoy-frontend" = "operator"
```

## Certificate layout

The example expects these files on the Envoy host:

- `/etc/envoy/certs/ca.crt`
- `/etc/envoy/certs/server.crt`
- `/etc/envoy/certs/server.key`

Remote operators need a client certificate and key signed by the same CA.

## Running Envoy

```bash
envoy -c examples/envoy-mtls/envoy.yaml
```

Envoy must be able to open the backend socket. The default UDS is created with
mode `0o600` owned by the daemon user, so run Envoy as that user (or as root);
any other identity gets `EACCES` on connect.

## Example client call

```bash
grpcurl \
  -cacert ca.crt \
  -cert client.crt \
  -key client.key \
  -import-path . \
  -proto proto/rustbgpd.proto \
  localhost:50052 \
  rustbgpd.v1.ControlService/GetHealth
```

## Operational notes

- **Every client Envoy admits becomes `local-operator` at operator tier.** The
  default UDS is owner-only, so the daemon authorizes its clients by filesystem
  ownership; the client certificate identity stops at Envoy and never reaches
  the authorization layer. mTLS is an admission gate here, not per-client RBAC
  — a monitoring-only certificate gets full mutating control. A daemon has at
  most one UDS listener and one TCP listener, so tier separation needs two
  different listeners: either cap the Envoy-facing UDS with an explicit
  `[global.telemetry.grpc_uds] max_tier` and do mutating work over a separate
  authenticated loopback TCP listener (`token_file` + `principal`, mapped in
  `[security.grpc.roles]`), or use the native mTLS TCP listener, which derives
  a per-certificate principal that `[security.grpc.roles]` maps to `observer` /
  `automation` / `operator`.
- Firewall the exposed Envoy listener to known management hosts even when mTLS
  is enabled.
- Prefer a dedicated management VLAN/interface instead of `0.0.0.0` where
  possible.
- This example intentionally leaves TLS termination outside rustbgpd itself.
  Native in-daemon mTLS is available for deployments that do not need a proxy.
