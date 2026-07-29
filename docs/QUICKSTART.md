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
sudo install -m 0755 rustbgpd rbgp rs-config-render /usr/local/bin/

rustbgpd --version && rbgp --version
```

The third binary, `rs-config-render`, is the
[IXP route-server config renderer](../tools/rs-config-render/README.md);
nothing below uses it, but it is in the same archive, so install it here
rather than hunting for it the day you stand up a route server. The
tarball also ships man pages and shell completions under `share/`;
[deployment.md](deployment.md#install) covers installing those and
pinning a specific version instead of `latest`.

### Or build from source

```bash
# Debian/Ubuntu build dependency for tonic/prost codegen.
sudo apt-get install -y protobuf-compiler

# Add -p rs-config-render for the route-server renderer.
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
an eBGP edge skeleton with a default-route-dropping import chain and a
default-deny export chain to fill in. Each profile is validated through the
real config loader before it is printed, and each passes
`rustbgpd --check --strict` as emitted: `lab` is permit-all in both
directions, but says so in an explicit chain rather than by omission.

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
rustbgpd --check --strict config.toml

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
# Add static peers at runtime. These are persisted back to the config file,
# which is rewritten in canonical form — see CONFIGURATION.md.
rbgp neighbor 10.0.0.5 add --remote-asn 65005
rbgp neighbor 203.0.113.2 add --remote-asn 65002 --role provider --strict-role
rbgp neighbor fe80::5054:ff:fe00:1%eth1 add --remote-asn 65101

# Create the peer group before adding a dynamic-neighbor accept range.
# Omitting both password fields creates a passwordless group; on an existing
# group the same omission preserves its current password.
cat > ix-members.json <<'JSON'
{
  "families": ["ipv4_unicast"],
  "route_server_client": true
}
JSON
rbgp peer-group set ix-members --from-file ix-members.json
rbgp --json peer-group get ix-members
rbgp dynamic-neighbor add 10.0.0.0/24 --peer-group ix-members
rbgp --json dynamic-neighbor list

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

Release images are published to GHCR; `:latest` tracks the newest release and
`:X.Y` pins a minor series (see
[deployment.md](deployment.md#container-image) for the full tag table).
`docker build -t rustbgpd .` produces the same lean runtime image under the
bare `rustbgpd` tag for local use only.

First adapt the `lab` config from step 2 for a container. Two of its values
are host defaults that do not work under Docker: state under `/tmp` is not on
the volume, and a `127.0.0.1` metrics bind is unreachable from a published
port.

```bash
sed -i \
  -e 's#/tmp/rustbgpd#/var/lib/rustbgpd#g' \
  -e 's#^prometheus_addr = .*#prometheus_addr = "0.0.0.0:9179"#' \
  config.toml
```

The `edge` profile already ships both values in their container form, so
starting from `--init-config edge` needs no such edit.

```bash
docker run -d --name rustbgpd \
  -v "$(pwd)/config.toml":/etc/rustbgpd/config.template.toml:ro \
  -v rustbgpd-state:/var/lib/rustbgpd \
  -p 179:179 -p 9179:9179 \
  --ulimit nofile=65536:524288 \
  ghcr.io/lance0/rustbgpd:latest \
  /bin/sh -c 'cp -n /etc/rustbgpd/config.template.toml /var/lib/rustbgpd/config.toml && exec rustbgpd /var/lib/rustbgpd/config.toml'
```

`--ulimit` is required, not tuning: the Docker default soft `nofile` is 1024,
which `rbgp doctor` fails outright because peers exhaust file descriptors at
scale.

Verify from the host over the published metrics port, and drive `rbgp` with
`docker exec` — the gRPC socket is a Unix socket inside the container, and the
runtime image is the only place an `rbgp` binary exists:

```bash
curl -fsS http://127.0.0.1:9179/livez    # ok
curl -fsS http://127.0.0.1:9179/readyz   # ready

docker exec rustbgpd rbgp health
docker exec rustbgpd rbgp summary
docker exec rustbgpd rbgp doctor
```

No `RUSTBGPD_ADDR` is needed: after the `sed`, the socket is at the CLI's
default `unix:///var/lib/rustbgpd/grpc.sock`.

Because the state directory now *is* the mounted volume, a `docker restart`
keeps the gRPC socket path, `config-history/`, the graceful-restart marker,
crash reports, and the event DB — not just the copied `config.toml`.

The config is seeded from a read-only template into the writable state volume
rather than bind-mounted in place. Config persistence rewrites the file with a
temp-file + rename, so the config's **directory** must be writable by the
daemon user: mount the file read-only and every mutating command
(`rbgp neighbor add`, policy edits, gNMI `Set`, `rbgp config apply`) is
rejected. Mount it read-write and the write still fails, because the image's
`/etc/rustbgpd` is root-owned and the daemon runs unprivileged.

Deployments that manage the config exclusively from the outside — SIGHUP after
an external edit, no runtime mutation — can mount it read-only and skip this.

Or use systemd with
[`examples/systemd/rustbgpd.service`](../examples/systemd/rustbgpd.service).

## Next steps

The [cookbook](cookbook/README.md) has receipt-proven configs and verification
commands for route reflection at scale, L3VPN reflection, IXP route servers,
monitoring feeds, EVPN fabric RRs, and `.rpol` policy.
