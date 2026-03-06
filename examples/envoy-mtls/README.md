# Envoy mTLS Frontend for rustbgpd

This example shows the recommended remote-management posture for rustbgpd:

- keep rustbgpd itself on loopback (or a local Unix domain socket when your
  deployment exposes one)
- terminate mutual TLS in Envoy
- expose only Envoy's frontend port to remote operators

The included [`envoy.yaml`](envoy.yaml) proxies gRPC over HTTP/2 from
`0.0.0.0:50052` to a local rustbgpd backend on `/var/lib/rustbgpd/grpc.sock`.

## Backend rustbgpd config

Keep the daemon on a local-only listener:

No extra gRPC config is required if you keep the default UDS:

```toml
[global]
runtime_state_dir = "/var/lib/rustbgpd"

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"
```

If you prefer a loopback TCP backend instead, add:

```toml
[global.telemetry.grpc_tcp]
address = "127.0.0.1:50051"
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

- Firewall the exposed Envoy listener to known management hosts even when mTLS
  is enabled.
- Prefer a dedicated management VLAN/interface instead of `0.0.0.0` where
  possible.
- This example intentionally leaves TLS termination outside rustbgpd itself.
  Native in-daemon mTLS remains a deferred hardening item.
