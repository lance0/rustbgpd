# Deploying rustbgpd

This is the end-to-end operator runbook: install, run, validate,
reload, observe, and upgrade. It's intentionally smaller than the M-
series interop matrix in [`INTEROP.md`](INTEROP.md) — that document
proves rustbgpd interops cleanly with FRR / BIRD / GoBGP, this one gets
*your* daemon onto *your* box.

For deeper references:

- [`CONFIGURATION.md`](CONFIGURATION.md) — every config field, with examples.
- [`reload-matrix.md`](reload-matrix.md) — which fields hot-apply vs. need a restart.
- [`OPERATIONS.md`](OPERATIONS.md) — debugging, log filtering, failure modes.
- [`SECURITY.md`](SECURITY.md) — firewalling, gRPC mTLS, authorization tiers.

## Status & expectations

rustbgpd is **public alpha overall**. The exception is the narrow,
machine-pinned [v1 route-server / route-reflector contract](v1-stable-contract.md),
which covers only its listed config fields, native gRPC signatures, CLI/JSON
contracts, and control-plane roles. Unlisted TOML and API surfaces can still
change between minor versions. See [`CHANGELOG.md`](../CHANGELOG.md) for
migration notes and run `rustbgpd --check <new config>` against the new binary
before swapping it in.

It runs on Linux. Other platforms are not tested.

Suitable for: lab pilots, data-center fabric pilots, IX route-server
pilots, automation-heavy control-plane work where the API surface
evolution is acceptable. Not yet suitable for fully unattended
production deployments where the operator can't react to a CHANGELOG
note.

## Install

### Pre-built binary tarball

Tagged releases publish `rustbgpd-linux-amd64.tar.gz` and
`rustbgpd-linux-arm64.tar.gz` under
[GitHub Releases](https://github.com/lance0/rustbgpd/releases). Each
ships `rustbgpd` (the daemon), `rbgp` (the CLI), and
`rs-config-render` (the route-server config renderer), plus man pages
and shell completions under `share/`:

```
rustbgpd, rbgp, rs-config-render        binaries
birdwatcher-adapter                     Alice-LG birdwatcher shim
LICENSE-MIT, LICENSE-APACHE             licenses
rustbgpd.schema.json                    config JSON Schema
share/man/man1/rbgp.1                   CLI man page
share/man/man8/rustbgpd.8               daemon man page
share/completions/rbgp.{bash,zsh,fish}  shell completions
share/systemd/rustbgpd.service          hardened systemd unit
share/systemd/rustbgpd-dataplane.conf   opt-in CAP_NET_ADMIN drop-in
share/monitoring/rustbgpd-overview.json Grafana dashboard
share/monitoring/rustbgpd-alerts.yml    Prometheus alert rules
share/monitoring/rustbgpd-alerts_test.yml promtool rule tests
```

The binaries are built against glibc 2.31; any distro at or above it
works (Debian 11+, Ubuntu 22.04+, RHEL/Rocky/Alma 9+).

The filename is the same on every release; `releases/latest/download/`
always resolves to the current tag, so this snippet never needs a
version bump.

<!-- release-install-contract:tarball:start -->
```sh
# Pick the right arch.
SUFFIX=linux-amd64    # or linux-arm64
TARBALL=rustbgpd-${SUFFIX}.tar.gz

curl -fL -o "$TARBALL" \
  "https://github.com/lance0/rustbgpd/releases/latest/download/${TARBALL}"
curl -fLO \
  "https://github.com/lance0/rustbgpd/releases/latest/download/checksums-${SUFFIX}.txt"
awk -v file="$TARBALL" '$2 == file || $2 == "./" file { print }' \
  "checksums-${SUFFIX}.txt" | sha256sum -c -
tar -xzf "$TARBALL"
sudo install -m 0755 rustbgpd rbgp rs-config-render /usr/local/bin/
sudo install -m 0644 share/man/man1/rbgp.1 /usr/local/share/man/man1/
sudo install -m 0644 share/man/man8/rustbgpd.8 /usr/local/share/man/man8/
sudo install -m 0644 share/completions/rbgp.bash \
  /usr/share/bash-completion/completions/rbgp

sudo useradd --system --home-dir /var/lib/rustbgpd \
  --shell /usr/sbin/nologin rustbgpd 2>/dev/null || true
sudo install -m 0644 share/systemd/rustbgpd.service \
  /etc/systemd/system/rustbgpd.service
sudo install -d -m 0755 /etc/rustbgpd
rustbgpd --init-config edge --stdout | \
  sudo tee /etc/rustbgpd/config.toml >/dev/null
sudo chmod 0640 /etc/rustbgpd/config.toml
sudo chgrp rustbgpd /etc/rustbgpd/config.toml

# Kernel-dataplane hosts only; control-plane-only hosts omit this drop-in.
sudo install -d /etc/systemd/system/rustbgpd.service.d
sudo install -m 0644 share/systemd/rustbgpd-dataplane.conf \
  /etc/systemd/system/rustbgpd.service.d/rustbgpd-dataplane.conf
```
<!-- release-install-contract:tarball:end -->

The man pages and completions are also generated on demand by the
binaries themselves (`rbgp man`, `rustbgpd --man`,
`rbgp completions bash|zsh|fish`), so an installed binary can always
regenerate them.

To pin to a specific tag for reproducibility, swap `latest` for the
version, e.g. `releases/download/v0.45.0/${TARBALL}`. SHA-256
checksums are published alongside each tarball as
`checksums-${SUFFIX}.txt`.

Verify:

```sh
rustbgpd --version
rbgp --version
rs-config-render --version
```

`rs-config-render` matters only if you run an IXP route server — it turns
`arouteserver template-context` output into rustbgpd configuration
([`tools/rs-config-render/`](../tools/rs-config-render/README.md)). It is
in the archive either way, so install it now rather than discovering it is
missing from a cron refresh later.

### Debian / RPM packages

Tagged releases also publish native packages built with
[nfpm](https://nfpm.goreleaser.com/) from the same binaries as the
tarballs ([`packaging/nfpm.yaml`](../packaging/nfpm.yaml)):

- `rustbgpd_X.Y.Z_{amd64,arm64}.deb` — Debian 11+, Ubuntu 22.04+
- `rustbgpd-X.Y.Z-1.{x86_64,aarch64}.rpm` — RHEL/Rocky/Alma 9+

```sh
# Debian / Ubuntu
curl -fLO https://github.com/lance0/rustbgpd/releases/latest/download/rustbgpd_X.Y.Z_amd64.deb
sudo apt-get install -y ./rustbgpd_X.Y.Z_amd64.deb

# RHEL / Rocky / Alma
sudo dnf install -y \
  https://github.com/lance0/rustbgpd/releases/download/vX.Y.Z/rustbgpd-X.Y.Z-1.x86_64.rpm
```

<!-- release-install-contract:native-package:start -->
The package installs the three binaries (`rustbgpd`, `rbgp`, and
`rs-config-render`) to `/usr/bin`, the hardened
systemd unit (see [systemd](#systemd) below — same unit, `ExecStart`
pointed at `/usr/bin`), man pages and shell completions, and creates
the `rustbgpd` system user (imperatively at install time, plus a
declarative `sysusers.d` file). A starter config lands at
`/etc/rustbgpd/config.toml` (mode `0640 root:rustbgpd`, never
overwritten on upgrade) — the [minimal profile](../examples/minimal/config.toml)
with its state paths set to `/var/lib/rustbgpd`. Version-matched monitoring
payloads land under `/usr/share/doc/rustbgpd/monitoring/`. Then:
<!-- release-install-contract:native-package:end -->

```sh
sudo $EDITOR /etc/rustbgpd/config.toml   # set ASN, router_id, neighbors
sudo systemctl enable --now rustbgpd
```

The kernel-dataplane capability drop-in ships as documentation at
`/usr/share/doc/rustbgpd/examples/rustbgpd-dataplane.conf`; copy it
into `/etc/systemd/system/rustbgpd.service.d/` only for deployments
that program the kernel (see below). Config-mutating RPCs (`rbgp
neighbor add`, gNMI `Set`) need `/etc/rustbgpd` writable by the
service user; the packaged default (`0750 root:rustbgpd`, read-only
for the daemon) supports the SIGHUP-reload workflow — `chown
rustbgpd /etc/rustbgpd /etc/rustbgpd/config.toml` if you want runtime
mutation.

### Verifying release artifacts

Each architecture has a `checksums-<arch>.txt` manifest covering its
tarball and native packages. Select the exact downloaded filename before
passing the row to `sha256sum`; checking the whole manifest fails when the
other package formats have not also been downloaded:

```sh
SUFFIX=linux-amd64
ARTIFACT=rustbgpd-linux-amd64.tar.gz
curl -fLO "https://github.com/lance0/rustbgpd/releases/latest/download/${ARTIFACT}"
curl -fLO "https://github.com/lance0/rustbgpd/releases/latest/download/checksums-${SUFFIX}.txt"
awk -v file="$ARTIFACT" '$2 == file || $2 == "./" file { print }' \
  "checksums-${SUFFIX}.txt" | sha256sum -c -
```

This detects a download that differs from the manifest published with the
GitHub release; it does not independently authenticate GitHub. The committed
`Cargo.lock` is the exact Rust dependency inventory for a tagged source tree.
Release binaries and containers are provided under the repository's license
terms and warranty disclaimers.

### Monitoring payloads

Every release archive carries its matching Grafana dashboard, Prometheus alert
rules, and promtool test suite under `share/monitoring/`. Native packages put
the same files under `/usr/share/doc/rustbgpd/monitoring/`. Keep
`rustbgpd-alerts.yml` beside `rustbgpd-alerts_test.yml`: the suite deliberately
uses the relative `rule_files` entry `rustbgpd-alerts.yml`.

Validate the shipped rules before loading them:

```sh
# From an extracted release tarball:
(cd share/monitoring && promtool test rules rustbgpd-alerts_test.yml)

# Or from a native package:
(cd /usr/share/doc/rustbgpd/monitoring && \
  promtool test rules rustbgpd-alerts_test.yml)
```

Copy or reference `rustbgpd-alerts.yml` from Prometheus's `rule_files`
configuration, then import `rustbgpd-overview.json` in Grafana. The
[Grafana guide](GRAFANA.md) supplies the matching scrape job and dashboard
setup; keep the payloads from one rustbgpd release together so rules and
metrics do not drift across versions.

### From source

```sh
# Prerequisites: Rust ≥ 1.95, protobuf-compiler
sudo apt-get install -y protobuf-compiler   # Debian/Ubuntu
git clone https://github.com/lance0/rustbgpd
cd rustbgpd
# Builds exactly what a deployment ships: the daemon, the rbgp CLI, and
# the route-server config renderer. (`--workspace` would also build
# dev/bench helpers you don't need.)
cargo build --release -p rustbgpd -p rustbgpctl -p rs-config-render
sudo install -m 0755 \
  target/release/rustbgpd target/release/rbgp target/release/rs-config-render \
  /usr/local/bin/
```

### Container image

A container image is built on every tagged release and published to
GHCR. Three tag flavors are available per the
`docker/metadata-action` rules in
[`.github/workflows/container.yml`](../.github/workflows/container.yml):

| Tag | Resolves to | Updates on |
|-----|-------------|------------|
| `:X.Y.Z` | exact version | nothing (immutable) |
| `:X.Y` | latest patch in the X.Y minor | each X.Y.z release |
| `:latest` | latest non-prerelease release | each minor or patch release |

Major-minor is the usual operator default — auto-receives bug-fix
releases but pins against minor-version churn. The examples in this
document use `:latest` so they stay copy-pasteable across releases;
substitute the major-minor tag of the series you standardize on:

```sh
docker pull ghcr.io/lance0/rustbgpd:latest
```

The published image is the Dockerfile's default `runtime` target:
lean, daemon + `rbgp` only, running as a nonroot `rustbgpd` user. No
dev/test/bench helpers are included. `rs-config-render` is deliberately
left out too: the IXP refresh loop is a host-side cron job that runs
`arouteserver` and the renderer next to each other and hands the daemon a
finished config directory, so the renderer belongs on the host, not in the
daemon's image. Install it from the tarball. If you'd rather build the
image locally:

```sh
docker build -t rustbgpd:latest .
```

The *development* image — adds `evpn-tester` / `evpn-monitor`,
`iproute2`, and the interop start script, and runs as root for lab
plumbing — is the `dev` target. It's what the M-series interop suite
and the soak harnesses run against:

```sh
docker build --target dev -t rustbgpd:dev .
```

## systemd

A hardened unit lives at
[`examples/systemd/rustbgpd.service`](../examples/systemd/rustbgpd.service).
It runs the daemon **unprivileged by default**: a dedicated `rustbgpd`
system user, the standard sandbox set (`NoNewPrivileges`,
`ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `StateDirectory` /
`RuntimeDirectory`), and a capability set of exactly
`CAP_NET_BIND_SERVICE` (bind port 179 as non-root). That is everything
a route-reflector / control-plane-only deployment needs.

Notes on the sandbox:

- `CAP_NET_BIND_SERVICE` lets the daemon bind port 179 without running
  as root. Nothing else is granted by default — in particular **not**
  `CAP_NET_ADMIN`, so the unprivileged unit cannot program the kernel.
- `ProtectSystem=strict` + explicit `ReadWritePaths` confines the
  daemon to `/var/lib/rustbgpd` (state) and `/etc/rustbgpd` (config).
- `ExecReload=kill -HUP` is the supported reload path. See the
  [reload matrix](reload-matrix.md) for which fields hot-apply vs.
  need a restart.
- `Restart=on-failure` is load-bearing. The daemon exits `0` only on an
  operator-initiated shutdown (SIGINT/SIGTERM, the `Shutdown` RPC) and
  `1` on a component failure it cannot recover from in place — the BGP
  listener failing to bind, a configured `prometheus_addr` health
  listener failing to bind, or the gRPC server exiting unexpectedly.
  None of these listeners is rebound without a restart, so the daemon exits
  rather than run on deaf; the supervisor's retry is the recovery path.
  With `RestartSec=5` a transient bind failure clears on the next
  attempt, and a permanent one (port held by another speaker, missing
  `CAP_NET_BIND_SERVICE`) repeats the bind error in the journal on every
  attempt. `rbgp doctor` reports the same cause against the down daemon
  through its `bgp.listener` check.

### Installation

The [Debian/RPM packages](#debian--rpm-packages) perform all of the
below on install (unit at `/lib/systemd/system`, `ExecStart` at
`/usr/bin`). The tarball commands above use its `share/systemd/` tree.
The following paths are only for a source checkout:

<!-- release-install-contract:source-checkout:start -->
```sh
sudo useradd --system --home-dir /var/lib/rustbgpd \
  --shell /usr/sbin/nologin rustbgpd
sudo install -m 0644 examples/systemd/rustbgpd.service \
  /etc/systemd/system/rustbgpd.service
sudo install -d -m 0755 /etc/rustbgpd
sudo install -m 0640 examples/minimal/config.toml /etc/rustbgpd/config.toml
sudo chgrp rustbgpd /etc/rustbgpd/config.toml   # readable by the service user
$EDITOR /etc/rustbgpd/config.toml    # set ASN, router_id, neighbors
sudo systemctl daemon-reload
sudo systemctl enable --now rustbgpd
```
<!-- release-install-contract:source-checkout:end -->

### Kernel dataplane: opt-in privilege drop-in

If — and only if — the config programs the kernel (`[[fib_tables]]`
per ADR-0061, `install_blackhole_discard`, or the EVPN VTEP/IRB
dataplane), the daemon needs `CAP_NET_ADMIN` for rtnetlink route /
nexthop programming, VXLAN + bridge FDB writes, and the
`RTNLGRP_NEIGH` subscription behind local-MAC learning. Grant it via
the shipped drop-in
[`examples/systemd/rustbgpd-dataplane.conf`](../examples/systemd/rustbgpd-dataplane.conf)
instead of editing the base unit — systemd merges capability sets, so
the drop-in *adds* `CAP_NET_ADMIN` on top of the unprivileged default:

```sh
sudo mkdir -p /etc/systemd/system/rustbgpd.service.d
sudo install -m 0644 examples/systemd/rustbgpd-dataplane.conf \
  /etc/systemd/system/rustbgpd.service.d/rustbgpd-dataplane.conf
sudo systemctl daemon-reload
sudo systemctl restart rustbgpd
```

RR-only boxes should **not** install this drop-in — the unprivileged
default is the point.

Dataplane host caveat: **if rustbgpd programs the kernel** on a host
that also runs systemd-networkd, set `ManageForeignRoutes=no`,
`ManageForeignRoutingPolicyRules=no`, and (where supported)
`ManageForeignNextHops=no` in `networkd.conf`. The defaults are
`yes`, and networkd will delete routes and next-hop groups it did
not create — including rustbgpd's, especially across a daemon
restart (ADR-0079). Co-residency with another daemon that claims
`proto bgp` kernel state (e.g. FRR zebra) is unsupported for the
same reason.

#### Reserved nexthop-ID ranges (EVPN dataplane)

When the EVPN VTEP/IRB dataplane is enabled, rustbgpd **exclusively
owns** four kernel nexthop-ID ranges, distinguished by the ID's high
nibble (deliberately offset from FRR's `0x1000`/`0x2000` tags so both
daemons can't collide on `NLM_F_REPLACE`):

| Range | Use |
|---|---|
| `0x3000_0000`–`0x3FFF_FFFF` | L2 per-VTEP FDB nexthop members (ADR-0059 aliasing ECMP) |
| `0x4000_0000`–`0x4FFF_FFFF` | L2 FDB nexthop groups (ADR-0059) |
| `0x5000_0000`–`0x5FFF_FFFF` | L3VXLAN per-VTEP nexthop members (all-active Type 5) |
| `0x6000_0000`–`0x6FFF_FFFF` | L3VXLAN FDB nexthop groups (all-active Type 5) |

This is a deployment contract: **no co-resident netlink writer may
create nexthop objects with IDs in these ranges** (`ip nexthop add
id …`, another routing daemon, orchestration tooling). rustbgpd
adopts objects it finds there across restarts and garbage-collects
the ones nothing references — an unrelated agent's object parked in
the range would be treated as rustbgpd state.

rustbgpd validates the shape of every in-range object it dumps at
startup adoption and during drift recovery (FDB flag, member vs
group structure matching the tag). An in-range object that does not
look like anything rustbgpd writes fails closed per ID: the object is
left untouched, excluded from adoption and from every reap/delete
path, its ID is quarantined so the allocator can never hand it out
(and thus never `NLM_F_REPLACE` over it), and the violation is
logged once and counted on the
`evpn_foreign_nhid_range_conflicts_total` Prometheus counter. A
nonzero counter means a co-resident writer is violating this
contract — find and remove that writer; the quarantined IDs are not
reclaimed until a daemon restart after the foreign objects are gone.

Note this shape check cannot distinguish a foreign object that is
byte-for-byte identical to what rustbgpd writes; stamping
`nh_protocol` on owned nexthop objects as a provenance marker is a
possible future defense-in-depth, not a substitute for this
contract (any netlink writer can set the same protocol value — it is
provenance, not kernel-enforced exclusivity).

### Operational checks

```sh
systemctl status rustbgpd            # is it running?
journalctl -u rustbgpd -f            # follow logs
systemctl reload rustbgpd            # SIGHUP → config reload
systemctl restart rustbgpd           # full restart (state drained)
```

## Docker / Docker Compose

A worked starting point at
[`examples/docker-compose/`](../examples/docker-compose/docker-compose.yml)
brings up rustbgpd alongside an FRR peer that advertises sample
prefixes — no real routers required.

```sh
cd examples/docker-compose
docker compose up -d --build
docker compose exec rustbgpd \
  rbgp -s http://127.0.0.1:50051 neighbor
docker compose down
```

For your own deployment:

- **State**: mount a volume at the daemon's `runtime_state_dir` so the
  GR restart marker and FIB ownership receipt survive container
  restarts. The daemon runs as uid/gid 999 and rewrites its config in
  place, so both host directories must be owned by that uid and the
  config must already exist — the image's default command is
  `rustbgpd /etc/rustbgpd/config.toml` and it will not create one:

  ```sh
  # One-time host prep.
  sudo install -d -o 999 -g 999 /etc/rustbgpd /var/lib/rustbgpd
  docker run --rm ghcr.io/lance0/rustbgpd:latest \
    rustbgpd --init-config edge --stdout > config.toml
  # Edit config.toml for your ASN, router ID, peers, and policy.
  sudo install -o 999 -g 999 -m 0600 config.toml /etc/rustbgpd/config.toml

  docker run --rm -d \
    --name rustbgpd \
    -v /etc/rustbgpd:/etc/rustbgpd \
    -v /var/lib/rustbgpd:/var/lib/rustbgpd \
    -p 179:179 \
    -p 9179:9179 \
    --ulimit nofile=65536:524288 \
    --cap-add=NET_BIND_SERVICE \
    --cap-add=NET_ADMIN \
    ghcr.io/lance0/rustbgpd:latest
  ```

  The `edge` profile is used because its `runtime_state_dir`,
  `grpc_uds` path, and `0.0.0.0` metrics bind are already the container
  forms; the `lab` profile's `/tmp` state directory and `127.0.0.1`
  metrics bind both need editing first.

- **File descriptors**: `--ulimit nofile` is required, not tuning. The
  Docker default soft limit is 1024, well under the 4096 floor
  `rbgp doctor` enforces, and peers exhaust descriptors at scale.

- **Writable config directory**: mount `/etc/rustbgpd` read-write and
  make it owned by the daemon user (`chown` the host directory to the
  container's `rustbgpd` uid) if you use runtime mutation — `rbgp
  neighbor add`, policy edits, gNMI `Set`, `rbgp config apply`. Config
  persistence rewrites the file with a temp-file + rename, so the
  *directory*, not just the file, has to be writable, and every mutating
  RPC is rejected without it. Mount it `:ro` only when the config is
  managed entirely from outside and reloaded with SIGHUP.

- **Health**: the image declares a `HEALTHCHECK` that runs `rbgp
  --json health` against the daemon's local gRPC socket and requires a
  self-reported healthy status — `docker ps` / orchestrators see the
  container flip `healthy` once the daemon answers. It probes rbgp's
  default endpoint (`unix:///var/lib/rustbgpd/grpc.sock`, the daemon
  default); if your config moves the socket, set `RUSTBGPD_ADDR` on
  the container to match.

- **Logs**: structured JSON when `[global.telemetry] log_format =
  "json"` is set; pipe to your log aggregator.

- **Networking**: Linux FIB integration and BFD require the container
  to share the host network namespace (or otherwise have access to
  the routing table you intend to program). The interop suite runs
  rustbgpd as a containerlab `kind: linux` node, which is the cleanest
  reference setup.

## Containerlab quick start

[Containerlab](https://containerlab.dev/) is the easiest way to get a
working rustbgpd ↔ FRR session on your laptop with no real routers.
The simplest topology in the repo is
[`tests/interop/m0-frr.clab.yml`](../tests/interop/m0-frr.clab.yml):

```yaml
name: m0-frr
topology:
  nodes:
    rustbgpd:
      kind: linux
      image: rustbgpd:dev
      cmd: sleep infinity
    frr:
      kind: linux
      image: quay.io/frrouting/frr:10.3.1
  links:
    - endpoints: ["rustbgpd:eth1", "frr:eth1"]
```

Bring it up:

```sh
# Build the dev image
docker build --target dev -t rustbgpd:dev .

# Deploy
sudo containerlab deploy -t tests/interop/m0-frr.clab.yml

# Inspect (the test driver scripts under tests/interop/scripts/ show
# the typical incantations for FRR vtysh + rbgp gRPC).

# Tear down
sudo containerlab destroy -t tests/interop/m0-frr.clab.yml --cleanup
```

For more topologies (route-reflector, EVPN, FlowSpec, BFD, etc.), see
[`INTEROP.md`](INTEROP.md).

## Recommended first production-ish topology

The smallest deployment that exercises the full operator loop —
**build → validate → reload → observe** — without depending on more
than one peer. This is your "did I install this correctly" gate before
scaling out.

1. **One rustbgpd instance + one FRR peer** (or any compliant BGP
   peer). Provision the peer first; record its address + AS.
2. **Prometheus scrape on `:9179`.** Add the scrape target in your
   Prometheus config:

   ```yaml
   - job_name: rustbgpd
     static_configs:
       - targets: ["10.0.0.1:9179"]
   ```

3. **Config validation.** Build the config, then:

   ```sh
   rustbgpd --check /etc/rustbgpd/config.toml
   ```

   Errors are rustc-style with file + line + carets; expect
   `config OK` on success. Run this **every time** before swapping the
   live config.

   A check that finds nothing to flag prints `config OK`. A check that
   flags something still exits 0, but the summary reads
   `config VALID, <n> WARNINGS — NOT a clean check` and the warnings are
   framed on stderr above it. The warning identifies a configured eBGP neighbor
   or dynamic range with no explicit policy in a direction: unfiltered when
   `[global] ebgp_requires_policy` is off, and carrying no routes in that
   direction when it is on. Neither is rejected — a permit-all route
   server is a legitimate configuration — but neither should reach
   production unnoticed.

4. **First start.**

   ```sh
   sudo systemctl start rustbgpd
   journalctl -u rustbgpd -f
   ```

   Watch for the session to reach `Established`:

   ```sh
   rbgp neighbor
   ```

5. **Edit + reload cycle.** Edit a copy of the config, then dry-run
   the diff of the candidate against the current on-disk config
   (`--diff` takes the candidate; the positional argument is the
   config to compare against, default `/etc/rustbgpd/config.toml`):

   ```sh
   cp /etc/rustbgpd/config.toml /tmp/new-config.toml
   $EDITOR /tmp/new-config.toml
   rustbgpd --diff /tmp/new-config.toml /etc/rustbgpd/config.toml
   ```

   When the diff looks right, install the candidate over
   `/etc/rustbgpd/config.toml` before reloading.

   `--diff` calls into the same `ConfigDiff` machinery the reload
   path uses; what it reports is what reload will do. Cross-reference
   against the [reload matrix](reload-matrix.md) to confirm which
   changes hot-apply and which are restart-required. Apply:

   ```sh
   sudo systemctl reload rustbgpd
   ```

6. **Restart cycle.** Confirm the FRR peer reconverges within the GR
   timer (GR is on by default):

   ```sh
   sudo systemctl restart rustbgpd
   # FRR should retain the routes during the restart window; rustbgpd
   # advertises R=1 in the GR capability on the next OPEN.
   ```

7. **Observability sanity-check.** Read at least one Prometheus counter
   and one neighbor field:

   ```sh
   curl -s http://10.0.0.1:9179/metrics \
     | grep -E "bgp_session_established_total|bgp_messages_received_total"
   rbgp neighbor 10.0.0.2
   ```

If all six steps work end-to-end, your install is sound. Scale from
there: add more peers, add policy chains, wire BMP / gNMI / MRT
according to your needs.

## Config validation workflow

These cover the config lifecycle, from bootstrap to reload:

| Command | What it does |
|---|---|
| `rustbgpd --init-config <lab\|edge> --stdout` | Print a curated, commented starter TOML to stdout and exit (file output is not yet supported). `lab` is a minimal single-box profile; `edge` is an eBGP edge skeleton with a default-route-dropping import chain and a default-deny export chain to fill in. Both use a mode-`0600` local UDS whose filesystem permissions authenticate access and whose stable `operator` principal is tier-authorized, set `[global] ebgp_requires_policy = true`, and pass `--check --strict` as emitted. Cannot be combined with `--check` / `--diff`. |
| `rustbgpd --check <file>` | Parse + validate; print `config OK`, `config VALID, <n> WARNINGS — NOT a clean check` (warnings framed on stderr; still exit 0), or a rustc-style diagnostic (exit 1). Does not start the daemon. |
| `rustbgpd --check --strict <file>` | The same check, but any warning exits 1 instead of 0 — for CI and deployment gates that must not accept a valid-but-risky config. A clean check still exits 0. `--strict` without `--check` is an error (exit 2). |
| `rustbgpd --diff <candidate> [<current>]` | Compare a candidate file against the current on-disk config (`<current>` defaults to `/etc/rustbgpd/config.toml`); print per-section change list with expected reload class. This is a static file-vs-file compare — to compare against the running daemon's view, use `rbgp config diff`. |
| `systemctl reload rustbgpd` (or `kill -HUP $(pidof rustbgpd)`) | Apply the diff. Live fields hot-apply; restart-required fields are pinned and logged at `ERROR` (the live values are kept). |

The validation pipeline is the same in all three places: TOML parse
→ `validate()` → `ConfigDiff`. A config that passes `--check` will
not error on `--diff`; a clean `--diff` will not error on reload.

## Observability

### Prometheus

The exporter binds at `[global.telemetry] prometheus_addr`. The same listener
serves `/livez` and `/readyz` for orchestrators. Key counters operators watch:

- **Session liveness** — `bgp_session_established_total`,
  `bgp_session_flaps_total`, `bgp_messages_received_total`,
  `bgp_messages_sent_total` (all by peer).
- **Loop / leak detection** — `bgp_as_path_loop_detected_total`,
  `bgp_rr_loop_detected_total`,
  `bgp_otc_routes_blocked_total{peer, reason}`
  (RFC 9234 / ADR-0071), `bgp_role_mismatch_total{peer, local_role,
  remote_role}`. Canonical `reason` values are documented in
  `docs/OPERATIONS.md` ("Ingress rejection / route-leak detection").
- **Route processing** — `bgp_rib_prefixes{peer, afi_safi}`,
  `bgp_rib_loc_prefixes{afi_safi}`, `bgp_max_prefix_exceeded_total`.
- **GR / FIB** — `bgp_gr_active_peers`, `bgp_gr_stale_routes`,
  `bgp_fib_routes_installed_total`, `bgp_fib_kernel_failures_total`.
- **Allocator** — `jemalloc_allocated_bytes`, `jemalloc_active_bytes`,
  `jemalloc_resident_bytes`, `jemalloc_mapped_bytes`. Present in builds
  with the `jemalloc` feature (the published container image and
  release tarballs); refreshed at scrape time. `allocated` is live
  application bytes, `resident` is jemalloc's contribution to RSS —
  a widening gap between the two is retained-but-unused allocator
  memory, the first thing to check before suspecting a leak.
- **Durable event outbox** (ADR-0072) —
  `bgp_event_outbox_committed_total{category}`,
  `bgp_event_outbox_dropped_total{category, reason}`,
  `bgp_event_outbox_db_size_bytes`,
  `bgp_event_outbox_latest_event_id`,
  `bgp_event_outbox_degraded`,
  `bgp_event_outbox_cursor_gap_total`. The degraded gauge is
  the alert-on-this signal — flips to `1` on a durability-impacting
  drop, decode/codec failure, or open failure since process start;
  does not auto-clear in v1, so any non-zero value warrants
  investigation. The
  cursor-gap counter alerts on collectors whose persisted
  `last_seen_event_id` fell below the daemon's retention
  floor — typically a sign the collector was offline longer
  than `[event_history].max_events` / `max_bytes` planned for.
  External collectors stream the cursor via the
  `SubscribeFromEvent` gRPC RPC; `examples/event-bridge/` is
  the reference skeleton — copy and replace the stdout writer
  with your Kafka / NATS / Vector / journald sink, persisting
  `last_seen_event_id` after the sink confirms durable receipt.
  See `[event_history]` in `CONFIGURATION.md` for tuning and
  recovery semantics, and the "Durable Event Cursor" section
  in `OPERATIONS.md` for the alert + sizing playbook.

**Policy filtering visibility — Prometheus.** `bgp_policy_routes_total
{peer, policy, direction, action}` attributes each import and export
policy evaluation to the terminal-decision policy in the chain with
`policy="…"` (the configured name) or `policy="inline"` for inline
statements and permit-all peers without an explicit chain. Initial
table dumps, route refreshes, dirty resyncs, and forced outbound
refreshes can increment export counters because they re-evaluate export
policy. The Prometheus counter is **monotonic for the lifetime of the
daemon process** — use Prometheus `rate()` / `increase()` to read it.

```promql
# Routes denied by a named filter on each peer's import side:
rate(bgp_policy_routes_total{direction="import", action="deny"}[5m])
```

**Policy evaluation errors — Prometheus.** `bgp_policy_eval_errors_total
{direction, kind}` counts routes denied by the fail-closed evaluation-
error rail (ADR-0103 Decision 4: checked-arithmetic failure, absent
operand, fuel/loop-cap exhaustion, ...). These denies also appear in
`bgp_policy_routes_total` as `action="deny"`; this counter separates
"the policy said no" from "the policy is broken". Any nonzero rate
deserves a look — `rbgp policy stats` names the failing chain, policy,
and term (`eval_errors` count + `last_error` per chain), and the
rate-limited daemon WARN carries the same blame line.

```promql
# Any policy erroring anywhere is alert-worthy:
sum by (kind) (rate(bgp_policy_eval_errors_total[5m])) > 0
```

**Policy filtering visibility — gRPC scalar aggregates.** `NeighborState`
carries four per-peer running totals to give operators a cheap
sanity-check on the labelled Prometheus counter:

| Field | Direction | Scope |
|---|---|---|
| `import_policy_routes_permitted` | import | Per session — resets on session-down (lives on `PeerSessionState`). |
| `import_policy_routes_denied` | import | Per session — same. |
| `export_policy_routes_permitted` | export | Per RIB peer-attach — resets on `handle_peer_down`, i.e. session-down. |
| `export_policy_routes_denied` | export | Per RIB peer-attach — same. |

Both directions reset together on the next session establishment, so
"how many routes did this session permit / deny in total" is straight
subtraction; "how many across reconnects" requires Prometheus history.
The CLI surfaces these in `rbgp neighbor <peer>` as a Policy Stats
block:

```
Policy Stats:
  Import — permitted: 1,247  denied: 31
  Export — permitted: 892    denied: 0
```

JSON output (`rbgp --json neighbor <peer>`) carries the same
fields under `import_policy_routes_permitted` / `import_policy_routes_denied`
/ `export_policy_routes_permitted` / `export_policy_routes_denied`,
elided when zero.

### BMP

If `[bmp]` is configured, rustbgpd opens a TCP session to the BMP
collector and exports per-peer Adj-RIB-In + Peer Up / Peer Down
events. See [`CONFIGURATION.md`](CONFIGURATION.md#bmp) for the schema.

### gNMI

The gNMI adapter (ADR-0070) exposes `Capabilities` / `Get` / `Subscribe`
telemetry plus the static numbered-neighbor `Set` subset over the same
sockets as the native API. Native gNMI is registered on
`[global.telemetry.grpc_tcp]` only when native mTLS is configured; the
`[global.telemetry.grpc_uds]` listener serves gNMI unconditionally as a
local-only extension. RFC 7951 JSON encoding. See [`GNMI.md`](GNMI.md)
for the path namespace and supported mutation leaves.

### CLI introspection

`rbgp` is the operator interface for read queries.

```sh
rbgp neighbor                  # list all neighbors
rbgp neighbor 10.0.0.2         # detail
rbgp neighbor 10.0.0.2 --compare 10.0.0.3  # live update-group relationship
rbgp rib                       # browse Loc-RIB
rbgp bfd                       # BFD sessions (ADR-0067)
rbgp evpn                      # EVPN instances + Type 2/3 RIB
rbgp top                       # live TUI dashboard
```

Most data-oriented read commands support `--json` for scripting. Commands with
fixed formats, such as `metrics`, `completions`, and `top`, keep their
command-specific output.

For an Established neighbor, `rbgp neighbor <addr>` reports whether the peer
negotiated Route Refresh, Enhanced Route Refresh, and Extended Messages, plus
the directional maximum BGP message size rustbgpd may send (4096 or 65535
bytes). The JSON fields preserve `false` as an explicit negotiated result and
omit values an older daemon did not expose; a missing live-session snapshot is
reported separately by `negotiation_available`.

## Upgrade & state migration

### Routine upgrade (no schema change)

```sh
sudo systemctl stop rustbgpd
sudo install -m 0755 /tmp/rustbgpd-vX.Y.Z /usr/local/bin/rustbgpd
sudo systemctl start rustbgpd
```

GR is on by default; after a coordinated shutdown rustbgpd advertises `R=1`
on the next OPEN. A GR-aware peer may retain eligible routes while sessions
rebuild, but rustbgpd advertises `forwarding_preserved = false`: this is not a
guarantee of forwarding continuity, and the peer may withdraw or replace routes
until normal convergence.

### Schema migration

TOML format is **not frozen** between minor versions while rustbgpd is
public alpha. Before upgrading across a minor version:

1. Read the CHANGELOG entry for the target version. Breaking config
   changes are called out under `### Changed` / `### Removed`.
2. Build the new binary or pull the new container image.
3. Run `rustbgpd --check /etc/rustbgpd/config.toml` against the **new**
   binary. Fix any errors before swapping.
4. Swap and start.

There is no in-place schema migration tool. If the CHANGELOG describes
a field rename, edit the config file by hand.

### Persistent state on disk

Runtime state lives in `runtime_state_dir` (default `/var/lib/rustbgpd`). The
v3 commit-confirm locator instead lives beside the lexical launch config so
startup finds the sole pending authority before trusting candidate contents:

Assign a distinct `runtime_state_dir` to every concurrently running rustbgpd
daemon. The directory is single-writer runtime state; sharing it between live
processes is unsupported even when their configuration files differ.

| Path | Purpose | Survives restart |
|---|---|---|
| `gr-restart.toml` | Graceful Restart coordination marker. Written on clean shutdown, read on startup to set the R-bit in OPEN. | Yes |
| `warm-bundle-v1/` | Optional owner-private shutdown checkpoint (`manifest.json` plus a content-addressed MRT artifact). Published only when `warm_cache_checkpoint_on_shutdown = true`; not restored on startup. | Yes |
| `<runtime_state_dir>/commit-confirm-journal.json` | Frozen locator-free v1 authority and v2 compatibility journal; secret-bearing normalized TOML. Production does not write it. | Until legacy recovery or verified residue cleanup |
| `<runtime_state_dir>/commit-confirm-v3-prior.toml` | Fixed v3 raw accepted prior; secret-bearing normalized TOML. Published first. | Until terminal cleanup; safe residue may remain |
| `<runtime_state_dir>/commit-confirm-v3-metadata.json` | Fixed confidential provenance, digest, and file-identity metadata; no raw TOML. Published after the raw prior. | Until terminal cleanup; safe residue may remain |
| `<absolute lexical config path>.commit-confirm-locator.json` | Confidential paths/digests and sole v3 pending boot authority; no raw TOML. Published last and checked before candidate contents. | Until durable unlink and parent sync make the transaction terminal |
| `config-history/*` | Last 20 owner-private, secret-bearing legacy TOML and v2 JSON records for `rbgp config history`; newest is index 0. V2 records hash but do not archive external sources and are rollback-eligible only when live sources exactly reproduce recorded provenance. Move this directory aside before downgrading to a version without v2 support. | Yes |
| `fib-owned.json` | FIB ownership receipt — which kernel routes the daemon installed (ADR-0061). Used to drain orphan installs on next start. | Yes |
| `grpc.sock` | gRPC UDS endpoint (if `[global.telemetry.grpc_uds]` configured). | Recreated on start |

The lexical config, metadata, and raw-prior paths resolve to absolute
identities. A writer or present pending object requires daemon-owned real
parents that are not group- or world-writable; locator absence carries no
authority or ordinary-startup storage requirement. Pending and staging files
must be daemon-owned regular files with mode `0600`; symlinks and special files
fail closed. Locator unlink plus parent `fsync` is terminal; only subsequent
verified metadata/raw cleanup and pending-directory `fsync` are warning-only.

Production writes v3. The v2 locator and locator-free v1 lanes are frozen
compatibility readers without conversion or dual-write. Finish or abort live
v1/v2 state before upgrade. Before downgrade, finish or abort v3 and never
delete its live locator manually; after it is terminal, verify the locator and
both fixed v3 files are absent. Also verify v2 locator/journal residue is absent
and move the complete v2 config-history directory aside for an older binary.

Routing state is **not restored**. The optional shutdown checkpoint contains
only eligible post-import-policy Adj-RIB-In views for future use; Loc-RIB,
Adj-RIB-Out, and policy evaluation state are not checkpointed, and the current
startup path loads none of it. Routing state rebuilds from peer routes after
restart. GR and checkpoint state support bounded control-plane restart
handling, but do not guarantee forwarding continuity; peers may withdraw or
replace routes, and therefore forwarding, until normal convergence.

The config file itself is mutable across runs: neighbor add/delete
operations via gRPC persist back to the config file (see
[`CONFIGURATION.md`](CONFIGURATION.md) → "Config Persistence").

## Sample profiles

The repo ships nine config profiles under
[`examples/`](../examples/) covering the standard deployment
shapes. Pick the closest match, copy, edit:

| Profile | File | Use case |
|---|---|---|
| Minimal | [`examples/minimal/config.toml`](../examples/minimal/config.toml) | Single eBGP peer; dev-friendly, state in `/tmp`. |
| IX route server | [`examples/route-server/config.toml`](../examples/route-server/config.toml) | RPKI, Add-Path, dual-stack, per-member policy chains. |
| Fabric edge / Linux FIB | [`examples/linux-edge-fib/config.toml`](../examples/linux-edge-fib/config.toml) | FIB integration on configured unicast tables; ECMP, weighted multipath. |
| EVPN VTEP leaf | [`examples/evpn-vtep-leaf/config.toml`](../examples/evpn-vtep-leaf/config.toml) | Bidirectional VTEP: kernel FDB → Type 2 origination. |
| EVPN RR fabric | [`examples/rr-evpn-fabric/config.toml`](../examples/rr-evpn-fabric/config.toml) | Route Reflector mode, stateless EVI (no `[[evpn_instances]]`). |
| Route collector | [`examples/route-collector/config.toml`](../examples/route-collector/config.toml) | Passive listener, MRT dumps, BMP export. |
| DDoS mitigation | [`examples/ddos-mitigation/config.toml`](../examples/ddos-mitigation/config.toml) | FlowSpec injection + RTBH (RFC 7999 BLACKHOLE). |
| Hosting provider | [`examples/hosting-provider/config.toml`](../examples/hosting-provider/config.toml) | iBGP injector for customer-prefix automation. |
| Docker Compose | [`examples/docker-compose/`](../examples/docker-compose/docker-compose.yml) | Quick-start with an FRR peer (gRPC on TCP). |

Each profile validates with `rustbgpd --check` out of the box; edit
the AS, addresses, and TLS material before deploying.

## Security checklist

See [`SECURITY.md`](SECURITY.md) for the full posture document. The
short version for first deployment:

- **Bind addresses.** `prometheus_addr`, `grpc_tcp.address`, `grpc_uds.path`
  default to listening on what the config says. Don't expose the
  Prometheus or gRPC endpoint to untrusted networks without
  authentication.
- **gRPC.** Use mTLS in production. Set `[security.grpc] enforcement = "tier"`
  and map principals to roles under `[security.grpc.roles]`
  (`observer` / `automation` / `operator`) per
  [`SECURITY.md`](SECURITY.md); the per-method tier matrix itself is
  compiled into the daemon (`crates/api/src/authz.rs`), not configured
  per-tier in TOML. UDS with a restrictive `mode`
  is fine for single-host operator access.
- **BGP authentication.** TCP-MD5 (RFC 2385) and TCP-AO (RFC 5925) are
  both supported. TCP-AO is preferred; see ADR-0062.
- **Firewall.** Allow inbound TCP/179 only from configured peer
  addresses (or address ranges if using `[[dynamic_neighbors]]`).
  Block everything else.

## Troubleshooting

| Symptom | Where to look |
|---|---|
| Session won't establish | `rbgp neighbor <addr>` + `journalctl -u rustbgpd -p warning` |
| Routes received but not installed | `rbgp rib`, then `rbgp rib received <peer> --rejected`; for the statement-level trace, `rbgp policy explain --neighbor <peer> --prefix <CIDR>` (opt-in: needs `[policy.explain] enabled = true`) |
| Reload didn't change behavior | `rustbgpd --diff <file>` + cross-reference [reload matrix](reload-matrix.md) |
| FIB programming failures | `bgp_fib_kernel_failures_total` Prometheus counter + `journalctl` for `kernel-dataplane` lines |
| EVPN-specific issues | [`evpn-vtep-troubleshooting.md`](evpn-vtep-troubleshooting.md) |
| Anything not above | [`OPERATIONS.md`](OPERATIONS.md) "Debugging" section |

For deeper investigation, raise the daemon log level globally via
`[global.telemetry] log_format = "json"` and per-peer via
`[[neighbors]] log_level = "debug"`. Restart required for the global
setting; per-peer log_level is **live** — re-applied on SIGHUP via a
tracing reload handle that rebuilds the filter (base level plus every
per-peer directive), so a level edit takes effect without a restart (see
the [reload matrix](reload-matrix.md)).

## Related

- [`OPERATIONS.md`](OPERATIONS.md) — start/stop, reload, upgrade, debugging.
- [`CONFIGURATION.md`](CONFIGURATION.md) — config reference.
- [`reload-matrix.md`](reload-matrix.md) — per-field reload classification.
- [`SECURITY.md`](SECURITY.md) — security posture + firewall guidance.
- [`INTEROP.md`](INTEROP.md) — M-series interop matrix.
- [`adr/`](adr/) — architectural decisions per protocol and design choice.
