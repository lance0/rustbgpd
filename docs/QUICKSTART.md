# Quickstart

This guide gets a single rustbgpd daemon running on a host with a starter
config, a local gRPC socket, health probes, and the `rbgp` CLI.

For the fastest no-host setup, use the Docker Compose lab in
[`examples/docker-compose/`](../examples/docker-compose/).

## 1. Install

```bash
# Debian/Ubuntu build dependency for tonic/prost codegen.
sudo apt-get install -y protobuf-compiler

cargo build --release -p rustbgpd -p rustbgpctl
```

The built binaries are:

- `target/release/rustbgpd` — daemon
- `target/release/rbgp` — CLI

## 2. Create a config

Generate a starter config from a built-in profile:

```bash
# `lab` = minimal single-box setup:
# gRPC over a local UDS, state under /tmp, Prometheus probes enabled.
./target/release/rustbgpd --init-config lab --stdout > config.toml
$EDITOR config.toml
```

Set at least the local ASN, router ID, and peer address. The `edge` profile is
an eBGP edge skeleton with a default-route-dropping import chain. Each profile
is validated through the real config loader before it is printed.

Prefer a checked-in starter file?

```bash
cp examples/minimal/config.toml config.toml
```

For route-server deployments, start from
[`examples/route-server/config.toml`](../examples/route-server/config.toml) and
the route-server cookbook.

## 3. Validate and run

```bash
# Validate config without starting the daemon.
./target/release/rustbgpd --check config.toml

# Preview what a config reload would change.
./target/release/rustbgpd --diff new-config.toml config.toml

# Start the daemon.
./target/release/rustbgpd config.toml
```

## 4. Verify

The minimal example uses `/tmp/rustbgpd` as its runtime state directory, so point
the CLI at that socket:

```bash
export RUSTBGPD_ADDR=unix:///tmp/rustbgpd/grpc.sock

rbgp health
rbgp summary    # alias for `rbgp neighbor` (--wide adds the classic MsgRcvd/MsgSent/State/PfxRcd columns)
rbgp rib
rbgp bfd       # BFD sessions, if configured
rbgp top       # live TUI dashboard
```

If `prometheus_addr` is configured, HTTP probes share that listener:

```bash
curl -fsS http://127.0.0.1:9179/livez
curl -fsS http://127.0.0.1:9179/readyz
```

With the systemd unit, the default CLI address is already
`unix:///var/lib/rustbgpd/grpc.sock`.

## 5. Operate

```bash
# Add static peers at runtime; persisted to config when the daemon was started
# with --config.
rbgp neighbor 10.0.0.5 add --asn 65005
rbgp neighbor 203.0.113.2 add --asn 65002 --role provider --strict-role
rbgp neighbor fe80::5054:ff:fe00:1%eth1 add --asn 65101

# Add a dynamic-neighbor accept range.
rbgp dynamic-neighbor add 10.0.0.0/24 --peer-group ix-members

# Manage Linux unicast FIB-export tables.
rbgp fib-table list

# Explain why a route was selected as best.
rbgp rib --prefix 10.0.0.0/24 --explain

# Inspect peer views with familiar route-server / RR terms.
rbgp rib recv 10.0.0.5
rbgp rib sent 10.0.0.5
rbgp policy counters

# Reload config after editing the file.
kill -HUP $(pidof rustbgpd)

# Graceful shutdown: writes the GR marker and notifies peers.
rbgp shutdown

# Support bundle for a bug report.
rbgp doctor
```

Enable shell completions:

```bash
rbgp completions bash > /etc/bash_completion.d/rbgp
# Or use the generated files in examples/completions/.
```

## Remote gRPC access

gRPC defaults to a local Unix domain socket. For remote access, configure native
mTLS on the TCP listener (`tls_cert_file`, `tls_key_file`, and
`tls_client_ca_file`; all three are required together). There is no
TLS-without-mTLS half-mode.

An Envoy proxy front-end is also supported for multi-host fan-out; see
[`examples/envoy-mtls/`](../examples/envoy-mtls/) and
[`docs/SECURITY.md`](SECURITY.md).

## Docker standalone

```bash
docker run -d --name rustbgpd \
  -v "$(pwd)/config.toml":/etc/rustbgpd/config.toml:ro \
  -v rustbgpd-state:/var/lib/rustbgpd \
  -p 179:179 -p 9179:9179 \
  rustbgpd
```

Or use systemd with
[`examples/systemd/rustbgpd.service`](../examples/systemd/rustbgpd.service).

## Next steps

The [cookbook](cookbook/README.md) has receipt-proven configs and verification
commands for route reflection at scale, L3VPN reflection, IXP route servers,
monitoring feeds, EVPN fabric RRs, and `.rpol` policy.
