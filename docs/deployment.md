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
- [`SECURITY.md`](SECURITY.md) — firewalling, gRPC mTLS, threat model.

## Status & expectations

rustbgpd is **public alpha**. The TOML config format and the gRPC API
are not yet frozen — breaking changes are possible between minor
versions. See [`CHANGELOG.md`](../CHANGELOG.md) for migration notes per
release and run `rustbgpd --check <new config>` against the new binary
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
ships `rustbgpd` (the daemon), `rbgp` (the preferred short CLI), and
`rustbgpctl` (the compatible long-form CLI). The
filename is the same on every release; `releases/latest/download/`
always resolves to the current tag, so this snippet never needs a
version bump.

```sh
# Pick the right arch.
SUFFIX=linux-amd64    # or linux-arm64
TARBALL=rustbgpd-${SUFFIX}.tar.gz

curl -fL -o "$TARBALL" \
  "https://github.com/lance0/rustbgpd/releases/latest/download/${TARBALL}"
tar -xzf "$TARBALL"
sudo install -m 0755 rustbgpd rbgp rustbgpctl /usr/local/bin/
```

To pin to a specific tag for reproducibility, swap `latest` for the
version, e.g. `releases/download/v0.30.0/${TARBALL}`. SHA-256
checksums are published alongside each tarball as
`checksums-${SUFFIX}.txt`.

Verify:

```sh
rustbgpd --version
rbgp --version
rustbgpctl --version
```

### From source

```sh
# Prerequisites: Rust ≥ 1.95, protobuf-compiler
sudo apt-get install -y protobuf-compiler   # Debian/Ubuntu
git clone https://github.com/lance0/rustbgpd
cd rustbgpd
cargo build --workspace --release
sudo install -m 0755 \
  target/release/rustbgpd target/release/rbgp target/release/rustbgpctl \
  /usr/local/bin/
```

### Container image

A container image is built on every tagged release and published to
GHCR. Three tag flavors are available per the
`docker/metadata-action` rules in
[`.github/workflows/container.yml`](../.github/workflows/container.yml):

| Tag | Resolves to | Updates on |
|-----|-------------|------------|
| `:0.30.0` | exact version | nothing (immutable) |
| `:0.30` | latest patch in the 0.30 minor | each 0.30.x release |
| `:latest` | latest non-prerelease release | each minor or patch release |

Major-minor is the usual operator default — auto-receives bug-fix
releases but pins against minor-version churn:

```sh
docker pull ghcr.io/lance0/rustbgpd:0.30
```

If you'd rather build locally:

```sh
docker build -t rustbgpd:dev .
```

The local image is what the M-series interop suite runs against; it's
the canonical *development* image.

## systemd

A hardened unit lives at
[`examples/systemd/rustbgpd.service`](../examples/systemd/rustbgpd.service):

```ini
[Unit]
Description=rustbgpd BGP daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/rustbgpd /etc/rustbgpd/config.toml
ExecReload=/bin/kill -HUP $MAINPID
StateDirectory=rustbgpd
RuntimeDirectory=rustbgpd
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/rustbgpd /etc/rustbgpd
PrivateTmp=yes
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Notes on the sandbox:

- `CAP_NET_BIND_SERVICE` lets the daemon bind port 179 without running
  as root. `CAP_NET_RAW` is required for the configured Linux FIB
  integration (ADR-0061) and for the optional BFD socket setup
  (ADR-0067).
- `ProtectSystem=strict` + explicit `ReadWritePaths` confines the
  daemon to `/var/lib/rustbgpd` (state) and `/etc/rustbgpd` (config).
- `ExecReload=kill -HUP` is the supported reload path. See the
  [reload matrix](reload-matrix.md) for which fields hot-apply vs.
  need a restart.
- **If rustbgpd programs the kernel** (`[[fib_tables]]`,
  `install_blackhole_discard`, or the EVPN dataplane) on a host that
  also runs systemd-networkd, set `ManageForeignRoutes=no`,
  `ManageForeignRoutingPolicyRules=no`, and (where supported)
  `ManageForeignNextHops=no` in `networkd.conf`. The defaults are
  `yes`, and networkd will delete routes and next-hop groups it did
  not create — including rustbgpd's, especially across a daemon
  restart (ADR-0079). Co-residency with another daemon that claims
  `proto bgp` kernel state (e.g. FRR zebra) is unsupported for the
  same reason.

### Installation

```sh
sudo install -m 0644 examples/systemd/rustbgpd.service \
  /etc/systemd/system/rustbgpd.service
sudo install -d -m 0755 /etc/rustbgpd
sudo install -m 0640 examples/minimal/config.toml /etc/rustbgpd/config.toml
$EDITOR /etc/rustbgpd/config.toml    # set ASN, router_id, neighbors
sudo systemctl daemon-reload
sudo systemctl enable --now rustbgpd
```

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
docker compose up -d
docker compose exec rustbgpd \
  rbgp -s http://127.0.0.1:50051 neighbor
docker compose down
```

For your own deployment:

- **State**: mount a volume at the daemon's `runtime_state_dir` so the
  GR restart marker and FIB ownership receipt survive container
  restarts:

  ```sh
  docker run --rm -d \
    --name rustbgpd \
    -v /etc/rustbgpd:/etc/rustbgpd:ro \
    -v /var/lib/rustbgpd:/var/lib/rustbgpd \
    -p 179:179 \
    -p 9179:9179 \
    --cap-add=NET_BIND_SERVICE \
    --cap-add=NET_RAW \
    ghcr.io/lance0/rustbgpd:0.30
  ```

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
docker build -t rustbgpd:dev .

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

4. **First start.**

   ```sh
   sudo systemctl start rustbgpd
   journalctl -u rustbgpd -f
   ```

   Watch for the session to reach `Established`:

   ```sh
   rbgp neighbor
   ```

5. **Edit + reload cycle.** Edit
   `/etc/rustbgpd/config.toml`, then dry-run the diff:

   ```sh
   rustbgpd --diff /etc/rustbgpd/config.toml
   ```

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

Four flags cover the config lifecycle, from bootstrap to reload:

| Command | What it does |
|---|---|
| `rustbgpd --init-config <lab\|edge> --stdout` | Print a curated, commented starter TOML to stdout and exit (file output is not yet supported). `lab` is a minimal single-box profile (gRPC over a local UDS, no auth); `edge` is an eBGP edge skeleton with a default-route-dropping import chain. Cannot be combined with `--check` / `--diff`. |
| `rustbgpd --check <file>` | Parse + validate; print `config OK` or rustc-style diagnostic. Does not start the daemon. |
| `rustbgpd --diff <file>` | Compute the diff against the running daemon's view; print per-section change list with expected reload class. |
| `systemctl reload rustbgpd` (or `kill -HUP $(pidof rustbgpd)`) | Apply the diff. Live fields hot-apply; restart-required fields are pinned and logged at `ERROR` (the live values are kept). |

The validation pipeline is the same in all three places: TOML parse
→ `validate()` → `ConfigDiff`. A config that passes `--check` will
not error on `--diff`; a clean `--diff` will not error on reload.

## Observability

### Prometheus

The exporter binds at `[global.telemetry] prometheus_addr`. Key
counters operators watch:

- **Session liveness** — `bgp_session_established_total`,
  `bgp_session_flaps_total`, `bgp_messages_received_total`,
  `bgp_messages_sent_total` (all by peer).
- **Loop / leak detection** — `bgp_as_path_loop_detected`,
  `bgp_rr_loop_detected`, `bgp_otc_routes_blocked_total{peer, reason}`
  (RFC 9234 / ADR-0071), `bgp_role_mismatch_total{peer, local_role,
  remote_role}`.
- **Route processing** — `bgp_routes_received_total`,
  `bgp_routes_installed_total`, `bgp_max_prefix_exceeded`.
- **GR / FIB** — `bgp_gr_active_peers`, `bgp_gr_stale_routes`,
  `bgp_fib_routes_installed_total`, `bgp_fib_kernel_failures_total`.
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
The CLI surfaces these in `rbgp neighbor show` as a Policy Stats
block:

```
Policy Stats:
  Import — permitted: 1,247  denied: 31
  Export — permitted: 892    denied: 0
```

JSON output (`rbgp --json neighbor show`) carries the same
fields under `import_policy_routes_permitted` / `import_policy_routes_denied`
/ `export_policy_routes_permitted` / `export_policy_routes_denied`,
elided when zero.

### BMP

If `[bmp]` is configured, rustbgpd opens a TCP session to the BMP
collector and exports per-peer Adj-RIB-In + Peer Up / Peer Down
events. See [`CONFIGURATION.md`](CONFIGURATION.md#bmp) for the schema.

### gNMI

If `[global.telemetry.grpc_tcp]` or `[global.telemetry.grpc_uds]` is
configured with TLS / mTLS, the gNMI adapter (ADR-0070) exposes
`Capabilities` / `Get` / `Subscribe` telemetry plus the static numbered-neighbor
`Set` subset over the same socket. RFC 7951 JSON encoding. See
[`GNMI.md`](GNMI.md) for the path namespace and supported mutation leaves.

### CLI introspection

`rbgp` is the primary operator interface for read queries. The compatible
`rustbgpctl` binary accepts the same commands.

```sh
rbgp neighbor                  # list all neighbors
rbgp neighbor 10.0.0.2         # detail
rbgp rib                       # browse Loc-RIB
rbgp bfd                       # BFD sessions (ADR-0067)
rbgp evpn                      # EVPN instances + Type 2/3 RIB
rbgp top                       # live TUI dashboard
```

Most data-oriented read commands support `--json` for scripting. Commands with
fixed formats, such as `metrics`, `completions`, and `top`, keep their
command-specific output.

## Upgrade & state migration

### Routine upgrade (no schema change)

```sh
sudo systemctl stop rustbgpd
sudo install -m 0755 /tmp/rustbgpd-vX.Y.Z /usr/local/bin/rustbgpd
sudo systemctl start rustbgpd
```

GR is on by default; the peer side advertises `R=1` on the next OPEN.
On a healthy GR-aware peer (FRR / BIRD / current GoBGP), the data path
stays up across the restart window.

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

Everything in `runtime_state_dir` (default `/var/lib/rustbgpd`):

| File | Purpose | Survives restart |
|---|---|---|
| `gr-restart.toml` | Graceful Restart coordination marker. Written on clean shutdown, read on startup to set the R-bit in OPEN. | Yes |
| `fib-owned.json` | FIB ownership receipt — which kernel routes the daemon installed (ADR-0061). Used to drain orphan installs on next start. | Yes |
| `grpc.sock` | gRPC UDS endpoint (if `[global.telemetry.grpc_uds]` configured). | Recreated on start |

Routing state — Adj-RIB-In, Loc-RIB, Adj-RIB-Out, policy evaluation —
is **not persisted**. It rebuilds from peer routes after restart (with
GR, the data path stays up while the rebuild happens).

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

- **Bind addresses.** `prometheus_addr`, `grpc_tcp.addr`, `grpc_uds.path`
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
| Routes received but not installed | `rbgp rib`, then check the import decision via `rbgp policy explain --neighbor <peer> --prefix <CIDR>` |
| Reload didn't change behavior | `rustbgpd --diff <file>` + cross-reference [reload matrix](reload-matrix.md) |
| FIB programming failures | `bgp_fib_kernel_failures_total` Prometheus counter + `journalctl` for `kernel-dataplane` lines |
| EVPN-specific issues | [`evpn-vtep-troubleshooting.md`](evpn-vtep-troubleshooting.md) |
| Anything not above | [`OPERATIONS.md`](OPERATIONS.md) "Debugging" section |

For deeper investigation, raise the daemon log level globally via
`[global.telemetry] log_format = "json"` and per-peer via
`[[neighbors]] log_level = "debug"`. Restart required for the global
setting; per-peer log_level is **live** (see the
[reload matrix](reload-matrix.md)).

## Related

- [`OPERATIONS.md`](OPERATIONS.md) — start/stop, reload, upgrade, debugging.
- [`CONFIGURATION.md`](CONFIGURATION.md) — config reference.
- [`reload-matrix.md`](reload-matrix.md) — per-field reload classification.
- [`SECURITY.md`](SECURITY.md) — security posture + firewall guidance.
- [`INTEROP.md`](INTEROP.md) — M-series interop matrix.
- [`adr/`](adr/) — architectural decisions per protocol and design choice.
