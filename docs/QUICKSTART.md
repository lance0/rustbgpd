# Quickstart

This guide gets a single rustbgpd daemon running on a host with a starter
config, a local gRPC socket, health probes, and the `rbgp` CLI.

For the fastest no-host setup, use the Docker Compose lab in
[`examples/docker-compose/`](../examples/docker-compose/).

## 1. Install

Grab the pre-built release tarball — no Rust toolchain, no compile:

```bash
SUFFIX=linux-amd64   # or linux-arm64
curl -fLO "https://github.com/lance0/rustbgpd/releases/latest/download/rustbgpd-${SUFFIX}.tar.gz"
curl -fLO "https://github.com/lance0/rustbgpd/releases/latest/download/checksums-${SUFFIX}.txt"
sha256sum -c "checksums-${SUFFIX}.txt"
tar -xzf "rustbgpd-${SUFFIX}.tar.gz"
sudo install -m 0755 rustbgpd rbgp /usr/local/bin/

rustbgpd --version && rbgp --version
```

The tarball also ships man pages and shell completions under `share/`;
[deployment.md](deployment.md#install) covers installing those and
pinning a specific version instead of `latest`.

### Or build from source

```bash
# Debian/Ubuntu build dependency for tonic/prost codegen.
sudo apt-get install -y protobuf-compiler

cargo build --release -p rustbgpd -p rustbgpctl
```

The built binaries are `target/release/rustbgpd` (daemon) and
`target/release/rbgp` (CLI); the commands below assume both are on
`PATH`.

## 2. Create a config

Generate a starter config from a built-in profile:

```bash
# `lab` = minimal single-box setup:
# gRPC over a local UDS, state under /tmp, Prometheus probes enabled.
rustbgpd --init-config lab --stdout > config.toml
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
rustbgpd --check config.toml

# Preview what a config reload would change.
rustbgpd --diff new-config.toml config.toml

# Start the daemon.
rustbgpd config.toml
```

## 4. Verify

The minimal example uses `/tmp/rustbgpd` as its runtime state directory, so point
the CLI at that socket:

<!-- rbgp-cli-conformance -->
```bash
export RUSTBGPD_ADDR=unix:///tmp/rustbgpd/grpc.sock

rbgp health
rbgp summary    # alias for `rbgp neighbor` (--wide adds MsgRcvd/MsgSent/Flaps/RRC/Slow/State/PfxRcd)
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
rbgp neighbor 10.0.0.5 add --remote-asn 65005
rbgp neighbor 203.0.113.2 add --remote-asn 65002 --role provider --strict-role
rbgp neighbor fe80::5054:ff:fe00:1%eth1 add --remote-asn 65101

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
# Or use the generated files in examples/completions/, or the
# share/completions/ files shipped in the release tarball.
```

Man pages ship in the release tarball (`share/man/man1/rbgp.1`,
`share/man/man8/rustbgpd.8`), and the binaries regenerate them on
demand:

```bash
rbgp man | man -l -
rustbgpd --man | man -l -
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

Release images are published to GHCR with versioned tags
(e.g. `ghcr.io/lance0/rustbgpd:0.51.0`); `docker build -t rustbgpd .`
produces the same lean runtime image locally.

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
