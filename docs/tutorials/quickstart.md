# Quickstart

> **Document class: CURRENT.**

Start and verify a single rustbgpd daemon.

This guide gets a single rustbgpd daemon running on a host with a starter
config, a local gRPC socket, health probes, and the `rbgp` CLI.

For the fastest no-host setup, use the Docker Compose lab in
[`examples/docker-compose/`](../../examples/docker-compose).

## 1. Install

Grab the pre-built release tarball — no Rust toolchain, no compile:

<!-- release-install-contract:tarball:start -->
```bash
SUFFIX=linux-amd64   # or linux-arm64
TARBALL="rustbgpd-${SUFFIX}.tar.gz"
curl -fLO "https://github.com/lance0/rustbgpd/releases/latest/download/${TARBALL}"
curl -fLO "https://github.com/lance0/rustbgpd/releases/latest/download/checksums-${SUFFIX}.txt"
awk -v file="$TARBALL" '$2 == file || $2 == "./" file { print }' "checksums-${SUFFIX}.txt" | sha256sum -c -
tar -xzf "$TARBALL"
sudo install -m 0755 rustbgpd rbgp rs-config-render birdwatcher-adapter /usr/local/bin/

sudo useradd --system --home-dir /var/lib/rustbgpd \
  --shell /usr/sbin/nologin rustbgpd 2>/dev/null || true
sudo install -m 0644 share/systemd/rustbgpd.service \
  /etc/systemd/system/rustbgpd.service
sudo install -d -m 0755 /etc/rustbgpd
rustbgpd --init-config edge | \
  sudo tee /etc/rustbgpd/config.toml >/dev/null
sudo chmod 0640 /etc/rustbgpd/config.toml
sudo chgrp rustbgpd /etc/rustbgpd/config.toml

rustbgpd --version && rbgp --version
```
<!-- release-install-contract:tarball:end -->

**Optional, kernel-dataplane hosts only.** Skip this unless the config
programs the kernel (`[[fib_tables]]`, `install_blackhole_discard`, or the
EVPN VTEP/IRB dataplane). The drop-in grants the service `CAP_NET_ADMIN`,
which a control-plane-only install does not need:

```bash
sudo install -d /etc/systemd/system/rustbgpd.service.d
sudo install -m 0644 share/systemd/rustbgpd-dataplane.conf \
  /etc/systemd/system/rustbgpd.service.d/rustbgpd-dataplane.conf
```

Releases from v0.70.0 onward also publish a verified installer, `install.sh`,
as a release asset (source:
[`packaging/install.sh`](../../packaging/install.sh)); earlier releases do not
include it. The tarball commands above remain the manual equivalent. The
[deployment guide](../how-to/deployment.md#verified-installer) covers the
installer's release-asset path, explicit tags, and prefix mode.

`rs-config-render` is the
[IXP route-server config renderer](../../tools/rs-config-render/README.md);
nothing below uses it, but it is in the same archive, so install it here
rather than hunting for it the day you stand up a route server. The
tarball also ships man pages, shell completions, and version-matched
monitoring payloads under `share/`. The Grafana dashboards and Prometheus
rules live in `share/monitoring/`; verify the alert pack without changing
its relative `rule_files` reference:

```bash
(cd share/monitoring && promtool test rules rustbgpd-alerts_test.yml)
```

Native packages install the same monitoring payloads under
`/usr/share/doc/rustbgpd/monitoring/`. Import `rustbgpd-overview.json` and,
when operating EVPN, the Alpha `rustbgpd-evpn.json` dashboard in Grafana; load
`rustbgpd-alerts.yml` from Prometheus.
[deployment.md](../how-to/deployment.md#monitoring-payloads) covers the paths, setup, and
pinning a specific release instead of `latest`.

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

The tarball systemd install above already generated the production-path
`edge` profile. For this foreground walkthrough (or a source checkout),
generate a disposable `lab` profile in the current directory:

```bash
# `lab` = minimal single-box setup:
# gRPC over a local UDS, state under /tmp, Prometheus probes enabled.
rustbgpd --init-config lab > config.toml
$EDITOR config.toml
```

For a real peer, set at least the local ASN, router ID, and peer address; the
[test peer](#bring-up-a-test-peer) below needs only the peer address changed.
The `edge` profile is an eBGP edge skeleton with a default-route-dropping
import chain and a default-deny export chain to fill in. Each profile is validated through the
real config loader before it is printed, and each passes
`rustbgpd --check --strict` as emitted: `lab` is permit-all in both
directions, but says so in an explicit chain rather than by omission.

For an installed-release route-server starting point, emit the self-contained
IPv4 two-member skeleton:

```bash
rustbgpd --init-config route-server > config.toml
$EDITOR config.toml
```

It defaults member import to deny, keeps route-server export explicitly
transparent, and has no external policy, dataset, RTR, or snapshot dependency.
Replace both member placeholders and their prefix limits, then install your
IRR/origin/RPKI import hygiene before accepting routes.

From a source checkout, prefer a checked-in starter file?

<!-- release-install-contract:source-checkout:start -->
```bash
cp examples/minimal/config.toml config.toml
```
<!-- release-install-contract:source-checkout:end -->

For a production route-server, continue with
[`examples/route-server/config.toml`](../../examples/route-server/config.toml),
the route-server cookbook, and [`rs-config-render`](../../tools/rs-config-render)
for generated member inventories.

### Bring up a test peer

"Establish a session" needs something to peer with. If you do not have a lab
router, run a throwaway FRR container on its own Docker network. It speaks
eBGP as AS 65002 to the `lab` profile's AS 65001 and announces one prefix,
`192.0.2.0/24`:

```bash
docker network create --subnet 172.31.254.0/24 rbgp-quickstart
cat > frr.conf <<'EOF'
router bgp 65002
 no bgp ebgp-requires-policy
 no bgp network import-check
 neighbor 172.31.254.1 remote-as 65001
 address-family ipv4 unicast
  network 192.0.2.0/24
 exit-address-family
EOF
docker run -d --name rbgp-quickstart-peer --network rbgp-quickstart \
  --ip 172.31.254.2 --cap-add NET_ADMIN --cap-add SYS_ADMIN \
  -v "$PWD/frr.conf:/etc/frr/frr.conf:ro" quay.io/frrouting/frr:10.7.1 \
  sh -c "sed -i 's/^bgpd=no/bgpd=yes/' /etc/frr/daemons && exec /usr/lib/frr/docker-start"

# Point the lab profile's neighbor at the container.
sed -i 's/^address = "10.0.0.2"/address = "172.31.254.2"/' config.toml
```

The host is `172.31.254.1` on that network, the address FRR expects the
session from. If `172.31.254.0/24` is already in use on your host, pick
another private subnet and replace every `172.31.254` in this block. The
[Compose demo](../../examples/docker-compose) is the no-host alternative: it
runs both routers in containers.

## 3. Validate and run

```bash
# Validate config without starting the daemon.
rustbgpd --check --strict config.toml

# Preview what a config reload would change: edit a copy, then compare.
sed 's/^hold_time = 90/hold_time = 30/' config.toml > new-config.toml
rustbgpd --diff new-config.toml config.toml

# Start the daemon in the foreground; use a second terminal for the steps
# below. Raise the shell's soft open-file limit first: `rbgp doctor` fails a
# daemon running with fewer than 4096.
ulimit -n 65536
rustbgpd config.toml
```

The `--diff` preview of that one-line edit, which exits 1 because the plan
has changes (0 means there is nothing to reload):

```text
Reload-applied changes:

  Neighbors:
    ~ 172.31.254.2:
        hold_time: 90 → 30  [session reset: OPEN renegotiation]

SIGHUP reload route: generation (one owned runtime generation; a late failure restores the prior generation)

Plan: 1 to change · 1 session will reset
```

The daemon refuses to start when the BGP listener cannot bind on either
address family — with the starter's `listen_port = 179` that means an
unprivileged run exits immediately with `Permission denied`. Either run as
root, grant the binary the bind capability
(`sudo setcap cap_net_bind_service=+ep $(command -v rustbgpd)`), or set an
unprivileged `listen_port` (>= 1024) in the config for lab sessions. The test
peer works with an unprivileged port because rustbgpd opens the session to it.

## 4. Verify

The `lab` profile (and `examples/minimal/config.toml`) uses `/tmp/rustbgpd` as
its runtime state directory, so point the CLI at that socket. gRPC access and
authorization need no configuration here: the local socket is owner-only, so its
clients are authorized as the implicit `local-operator` principal — even a
config with no gRPC or `[security.grpc]` section at all gets this listener by
default. Remote (TCP) or named access needs explicit principals and roles; see
[CONFIGURATION.md](../reference/configuration.md#securitygrpc).

<!-- rbgp-cli-conformance -->
```bash
export RUSTBGPD_ADDR=unix:///tmp/rustbgpd/grpc.sock

rbgp health
rbgp summary    # alias for `rbgp neighbor` (--wide adds Source/MsgRcvd/MsgSent/Flaps/RRC/Slow/State/PfxRcd)
rbgp rib
rbgp bfd       # BFD sessions, if configured
rbgp top       # live TUI dashboard
```

With the [test peer](#bring-up-a-test-peer), the session comes up within a
few seconds of starting the daemon, and `rbgp summary` shows its one prefix:

```text
Neighbor     AS    State       Uptime   Rx Pfx Tx Pfx  Description
172.31.254.2 65002 Established 00:00:02      1      0  lab-peer
```

`Tx Pfx 0` is expected: the only route came from that peer, and it is not
advertised back to it.

From the TUI peer detail, press `r` to open the on-demand route explorer: `v`
cycles the global Best table and the peer's Received, Advertised, and Rejected
tables, `f` toggles IPv4/IPv6 unicast, `/` sets an exact prefix filter, and
`n`/`p` follow server pages (`Space`/`PgDn` move within one). `Enter` on a
Best row, or `e` with a typed or selected prefix, shows whether the prefix
would be advertised to that peer or denied, including the ordered export gates
and policy reasons. This is an on-demand view, not a live RIB feed.

If `prometheus_addr` is configured, HTTP probes share that listener:

```bash
curl -fsS http://127.0.0.1:9179/livez
curl -fsS http://127.0.0.1:9179/readyz
```

With the systemd unit, the default CLI address is already
`unix:///var/lib/rustbgpd/grpc.sock`.

### Optional: serve the Birdwatcher REST subset

<!-- release-install-contract:birdwatcher-production:start -->
Release tarballs, native `.deb`/`.rpm` packages, and the production container
include `birdwatcher-adapter`. A package install can serve Alice-LG from the
daemon's local socket without exposing gRPC on TCP:

```bash
sudo -u rustbgpd birdwatcher-adapter \
  --grpc-addr unix:///var/lib/rustbgpd/grpc.sock \
  --listen 127.0.0.1:8080
```

Use `--grpc-addr http://127.0.0.1:50051` for a configured TCP listener. The
adapter may start before rustbgpd: requests return `502 Bad Gateway` until the
daemon/socket is available, then recover without restarting the adapter. The
release does not install a service unit for it; supervise it with the rest of
the Alice-LG deployment. Full endpoint and token guidance is in the
[adapter README](../../examples/birdwatcher-adapter/README.md). The default socket
grants operator-tier `local-operator`; use its dedicated authenticated
`observer` listener pattern for least privilege.
<!-- release-install-contract:birdwatcher-production:end -->

## 5. Operate

```bash
# Add static peers at runtime. These are persisted back to the config file,
# which is rewritten in canonical form — see CONFIGURATION.md.
rbgp neighbor 10.0.0.5 add --remote-asn 65005
rbgp neighbor 203.0.113.2 add --remote-asn 65002 --role provider --strict-role
# A link-local peer carries its interface as a zone. Placeholder: replace
# eth1 with the host's interface before running it.
# rbgp neighbor fe80::5054:ff:fe00:1%eth1 add --remote-asn 65101

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

# Explain why the test peer's route was selected as best.
rbgp rib --prefix 192.0.2.0/24 --explain

# Inspect peer views with familiar route-server / RR terms.
rbgp rib recv 172.31.254.2
rbgp rib sent 172.31.254.2
rbgp policy counters

# Reload config after editing the file.
kill -HUP $(pidof rustbgpd)

# Support bundle for a bug report; it needs the daemon running.
rbgp doctor

# Graceful shutdown: writes the GR marker and notifies peers. On a terminal
# it asks for confirmation first; --yes skips the prompt.
rbgp shutdown --yes

# Remove the test peer.
docker rm -f rbgp-quickstart-peer
docker network rm rbgp-quickstart
```

Enable shell completions:

```bash
rbgp completions bash | sudo tee /etc/bash_completion.d/rbgp >/dev/null
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
[`examples/envoy-mtls/`](../../examples/envoy-mtls) and
[`docs/reference/security.md`](../reference/security.md).

## Docker standalone

Release images are published to GHCR; `:latest` tracks the newest release and
`:X.Y` pins a minor series (see
[deployment.md](../how-to/deployment.md#container-image) for the full tag table).
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
  --stop-timeout=1920 \
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

`--stop-timeout=1920` gives an explicit container stop 32 minutes to wait for
an owned runtime-config mutation. If settlement becomes ambiguous, readiness
fails and new persisted mutations are rejected before the daemon exits 70:
within five seconds when ambiguity is detected, or by 30 minutes plus five
seconds when an owner goes silent. Docker does not restart this standalone
example; production supervision should bound retries.

Or use systemd with
[`examples/systemd/rustbgpd.service`](../../examples/systemd/rustbgpd.service).

## Next steps

The [cookbook](../cookbook/README.md) has receipt-proven configs and verification
commands for route reflection at scale, L3VPN reflection, IXP route servers,
monitoring feeds, EVPN fabric RRs, and `.rpol` policy.
