# Configuration Reference

rustbgpd is configured via a single TOML file, passed as the first argument to the daemon:

```
rustbgpd /etc/rustbgpd/config.toml
```

The config file defines the initial boot state. The canonical live compound
mutation path is the gRPC config transaction lifecycle (plan, snapshot-fenced
apply, and optional commit-confirmed confirm/abort). Focused RPCs can add,
remove, enable, and disable peers without restarting the daemon and persist
supported mutations back to the config file. Those writes rewrite the file in
canonical form and do not preserve comments or formatting — read
[Config Persistence](#config-persistence) before you make the first runtime
change. `SIGHUP` is the file-driven compatibility/reconcile path; it follows
the reload matrix and is not an atomic compound-mutation API. Starting with
zero `[[neighbors]]` is valid when all peers are managed via gRPC. The exact
compatibility boundary is the narrow
[v1 RS/RR inventory](v1-stable-contract.md), not the full schema.

> **Reload behavior.** For a per-field table of which config keys hot-apply,
> which are restart-required, and which are rejected at parse time, see
> [`reload-matrix.md`](reload-matrix.md). This page documents *what* each
> field means; the matrix documents *when* a change takes effect.
>
> **Deploying it.** For the end-to-end install + lifecycle walkthrough
> (systemd setup, Docker, containerlab quick-start, upgrade, observability),
> see [`deployment.md`](deployment.md).

---

## Editor integration (JSON Schema)

A JSON Schema for the full config surface ships as
[`docs/rustbgpd.schema.json`](rustbgpd.schema.json) (also emitted by
`rustbgpd --dump-config-schema`, included in the release tarballs, and
published as a standalone release asset). Any TOML language server that
supports JSON Schema — [taplo] / the VS Code **Even Better TOML**
extension — will give as-you-type completion, inline validation, and
hover docs for every field on this page.

Point your editor at the schema with a directive at the top of the
config file:

```toml
#:schema https://github.com/lance0/rustbgpd/releases/latest/download/rustbgpd.schema.json
[global]
# ...
```

or associate it by path in `.taplo.toml`:

```toml
[[rule]]
include = ["**/rustbgpd*.toml", "/etc/rustbgpd/*.toml"]
url = "https://github.com/lance0/rustbgpd/releases/latest/download/rustbgpd.schema.json"
```

(Use a local `file://` URL or the tarball copy for air-gapped hosts.)

To validate a config from the command line without the daemon:

```
taplo check --schema file://$PWD/docs/rustbgpd.schema.json /etc/rustbgpd/config.toml
```

Note that the schema checks structure, types, and enum values; semantic
rules (ASN/hold-time ranges, cross-field requirements, name references)
are still enforced by `rustbgpd --check`. Run both for full coverage.

Every table in the schema rejects unknown keys, and a typo'd key is
diagnosed with the file/line/column, the enclosing table, and the
closest valid key(s):

```
error: failed to parse config
   --> /etc/rustbgpd/config.toml:13:1
   |
13 | route_server_clint = true
   | ^^^^^^^^^^^^^^^^^^ unknown field `route_server_clint` in [[neighbors]]; did you mean `route_server_client`?
```

If no valid key is close enough, the error lists the full set of keys
accepted at that position instead. Lines carrying secret material
(`md5_password`, `tcp_ao` keys) stay redacted in these excerpts even
when the key itself is the typo.

To see what a **running** daemon is actually using — the post-defaults
config, with peer-group inheritance and computed defaults (`hold_time`,
`send_hold_time`, GR timers, address families) materialized on every
static neighbor — dump it live:

```
rbgp config effective            # normalized TOML
rbgp -j config effective         # same document as JSON
```

Secret material (`md5_password`, `tcp_ao` keys) is replaced with
`<redacted>` before it leaves the daemon; a dump containing the
placeholder deliberately fails `rustbgpd --check`, so restore real
secrets before reusing a dump as a config file.

### SchemaStore submission (not yet submitted)

Once submitted to [SchemaStore](https://github.com/SchemaStore/schemastore),
editors pick the schema up automatically with no `#:schema` directive.
The catalog entry to add to `src/api/json/catalog.json` in a PR there:

```json
{
  "name": "rustbgpd",
  "description": "rustbgpd BGP daemon configuration",
  "fileMatch": ["rustbgpd.toml", "**/rustbgpd/config.toml", "**/rustbgpd/*.toml"],
  "url": "https://github.com/lance0/rustbgpd/releases/latest/download/rustbgpd.schema.json"
}
```

(SchemaStore requires the entry sorted alphabetically by `name`, and a
positive + negative test fixture under `src/test/rustbgpd/`.)

[taplo]: https://taplo.tamasfe.dev/

---

## `[global]`

Required. Defines the local BGP speaker identity.

| Field               | Type   | Required | Default              | Description                        |
|---------------------|--------|----------|----------------------|------------------------------------|
| `asn`               | u32    | yes      | --                   | Local autonomous system number; AS 0 is rejected at startup |
| `router_id`         | string | yes      | --                   | Non-zero BGP Identifier in IPv4 dotted-quad form; `0.0.0.0` is rejected at startup |
| `listen_port`       | u16    | yes      | --                   | TCP port to listen on (typically 179). The daemon listens on both address families — `0.0.0.0` and `[::]` — at this port; if one family cannot be bound (for example IPv6 disabled on the host) it is logged and skipped while the other keeps serving. Startup fails only when neither family binds |
| `dynamic_neighbor_limit` | u32 | no     | `100`                | Maximum number of auto-accepted dynamic peers (1--5000) |
| `worker_threads`    | usize  | no       | `min(cores, 8)`      | Tokio runtime worker threads. Unset caps to `min(CPU parallelism, 8)` to avoid over-provisioning the async runtime (one worker + stack reservation per core) on a high-core host for this I/O-bound daemon — reduces virtual-address reservation and scheduler footprint (RSS-neutral in benchmarks). `0` means unset. `RUSTBGPD_WORKER_THREADS` overrides. **Restart-required** (runtime built once at startup). |
| `runtime_state_dir` | string | no       | `"/var/lib/rustbgpd"` | Directory for daemon-owned runtime state (GR restart marker, optional warm checkpoint, FIB ownership receipt, and gRPC socket) |
| `warm_cache_checkpoint_on_shutdown` | bool | no | `false`             | Publish a bounded daemon-private routing checkpoint during coordinated shutdown. **Restart-required.** Publication only; startup does not restore routes. |
| `cluster_id`        | string | no       | --                    | Route reflector cluster ID (must be valid IPv4; enables RR mode) |
| `honor_graceful_shutdown` | bool | no  | `false`              | Enable RFC 8326 §4 receiver behavior on EBGP imports — see below |
| `honor_blackhole`   | bool   | no       | `false`              | Enable RFC 7999 receiver scoping on EBGP imports — see below |
| `install_blackhole_discard` | bool | no | `false`              | Install kernel blackhole routes for accepted RFC 7999 host routes — see below |
| `allow_blackhole_broad_prefixes` | bool | no | `false`           | Permit non-host BLACKHOLE discard installs when the FIB slice is enabled |
| `ebgp_requires_policy` | bool | no       | `false`              | RFC 8212: require explicit operator import/export policy on eBGP sessions; a direction without one runs a reserved internal deny. **Restart-required** — see below |
| `multipath_relax`   | bool   | no       | `false`              | ADR-0066 multipath-relax: group unicast ECMP candidates by `AS_PATH` *length* instead of an exact `AS_PATH` match (FRR's `bgp bestpath as-path multipath-relax`). Best-path-wide; inert unless a `[[fib_tables]]` sets `maximum_paths`, `maximum_paths_ebgp`, or `maximum_paths_ibgp` above `1` |
| `link_bandwidth_weighted` | bool | no   | `false`              | ADR-0068 weighted multipath: weight unicast ECMP next-hops by the lowest finite nonnegative RFC 10005 Link Bandwidth value when the whole equal-cost group carries a positive one; zero, missing, or unusable values fall back to equal cost. Best-path-wide; inert unless a `[[fib_tables]]` sets `maximum_paths`, `maximum_paths_ebgp`, or `maximum_paths_ibgp` above `1` |

Startup validation rejects local AS 0 (RFC 7607 §2) and BGP Identifier zero
(RFC 6286 §2.1) before any listener or peer session starts.

```toml
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
runtime_state_dir = "/var/lib/rustbgpd"
warm_cache_checkpoint_on_shutdown = false
honor_graceful_shutdown = true
honor_blackhole = true
install_blackhole_discard = false
allow_blackhole_broad_prefixes = false
```

`runtime_state_dir` must be writable by the rustbgpd process. In containers or
non-root deployments, override the default to a mounted writable path (for
example `/var/lib/rustbgpd` on a volume, or `/data/rustbgpd`).

The **directory holding the config file** must also be writable by the
rustbgpd process if you use runtime mutation. Every accepted `rbgp neighbor
add` / `delete`, policy or peer-group edit, dynamic-range change, gNMI `Set`,
and `rbgp config apply` is written back to the config file with a temp-file +
rename, which creates `<config>.tmp` alongside it. Without a writable
directory those RPCs are rejected with `FAILED_PRECONDITION` before they
change anything — the session, its counters, and the wire are untouched. A
config directory that is read-only on purpose (external configuration
management, SIGHUP-only reload) is supported; the rejection is the contract,
not a failure mode to work around.

`warm_cache_checkpoint_on_shutdown` is an opt-in, restart-required publication
step. During a coordinated shutdown, rustbgpd has up to 30 seconds to capture
eligible established static peers' post-import-policy Adj-RIB-In views and
atomically publish a content-addressed MRT artifact plus `manifest.json` under
`<runtime_state_dir>/warm-bundle-v1`. The bundle is capped at 512 MiB, binds
the exact effective configuration, resolved import policies, live peer/family
identity, and restart-marker generation, and is readable only through the
daemon-private runtime-state directory. If capture or publication fails, the
daemon still publishes a generationless Graceful Restart marker.
After a new manifest is durably committed, rustbgpd removes superseded
content-addressed snapshots and recognizable interrupted-write temporary
files from that pinned private directory. Cleanup failure is logged but does
not invalidate the current manifest or its snapshot; unknown files are left
untouched. Startup also performs the same bounded, descriptor-relative cleanup
before shutdown publication is armed: a structurally valid, byte-stable
manifest always protects its selected snapshot, a missing manifest permits
orphan cleanup, and a corrupt, unsafe, oversized, or changed manifest deletes
nothing. One undeletable stale entry is reported but does not suppress later
entries in deterministic filename order.

Turning `warm_cache_checkpoint_on_shutdown` back off does not remove the last
committed bundle: nothing scavenges `<runtime_state_dir>/warm-bundle-v1` once
the option is disabled. The bundle contains routing table contents (see the
shutdown warm-checkpoint confidentiality note in SECURITY.md), so delete that
directory manually if the cached routing data must not persist.

Every concurrently running rustbgpd daemon must use a distinct
`runtime_state_dir`. Sharing one runtime-state directory between live daemon
processes is unsupported because the restart marker, warm checkpoint, FIB
ownership receipt, and Unix socket are all single-writer state.

This option does **not** make startup restore routes: no cached route is loaded,
selected, installed, or advertised. A successful checkpoint only causes the GR
restart marker to carry the matching generation. Marker v3 protection requires
Linux 5.6+ with `CONFIG_TIME_NS`, a readable valid
`/proc/sys/kernel/random/boot_id`, inspectable `/proc/self/ns/time`
device/inode, readable valid `/proc/self/timens_offsets`, and a sampleable and
representable `CLOCK_BOOTTIME` deadline. When the complete live domain matches
exactly at startup, that deadline is insulated from discontinuous
`CLOCK_REALTIME` steps between shutdown and startup. Otherwise startup uses the
marker's generation-bound wall deadline, capped by the current configured
restart maximum; a forward wall-clock step can shorten or expire that fallback.
If publication cannot form a complete v3 marker, it emits generation-bound v2.
Checkpoint failure similarly selects a generationless v3 when available or
wall-only v1 marker. The current boot path still rebuilds all routing state from
peers.

`dynamic_neighbor_limit` caps the number of active peers auto-created from
`[[dynamic_neighbors]]` ranges. When omitted, rustbgpd allows up to 100 dynamic
peers at a time.

### `apply_bum_enforcement` — top-level (document-root) key

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `apply_bum_enforcement` | bool | no | `true` (since v0.23.0) | Apply Gate 8b BUM-suppression filters to the kernel per-port `IFLA_BRPORT_*_FLOOD` triplet. **Restart-required.** Default flipped to `true` after the Gate 8b 24 h MAC-churn soak (2026-05-16) and the M37 local-origination 24 h MAC-churn soak (2026-05-19) both passed. Operators who need the prior observe-only posture must set `apply_bum_enforcement = false` explicitly. |

This is a **document-root** key — a bare key written outside any `[section]`
header (typically at the very top of the file, before `[global]`), **not** a
`[global]` key. `[global]` is a `deny_unknown_fields` section, so placing
`apply_bum_enforcement` inside it makes the daemon refuse to start with a TOML
parse error.

```toml
# top of file, outside any section header
apply_bum_enforcement = false

[global]
asn = 65001
# ...
```

### `honor_graceful_shutdown` — RFC 8326 receiver behavior

When `true`, rustbgpd appends an implicit chain-tail rule on every
EBGP peer's import chain:

```
match community = GRACEFUL_SHUTDOWN (65535:0) → permit, set local_pref = 0
```

Routes carrying the `GRACEFUL_SHUTDOWN` well-known community land in the RIB
with `LOCAL_PREF = 0`, demoting the path so any non-shutting peer's path is
preferred during best-path selection. The originating peer can then close the
session knowing that traffic has already shifted.

The implicit rule sits at the **end** of the resolved chain so it wins the
last-writer accumulation against any operator policy that also sets
`LOCAL_PREF`. Operator denies still short-circuit normally — denied routes
don't survive to the demotion step.

iBGP peers (`remote_asn == global.asn`) are exempt because `LOCAL_PREF` is
preserved within an AS; re-applying the demotion per iBGP hop would clobber
values set legitimately at the upstream EBGP edge. Confederation gating is
tracked in [`ROADMAP.md`](../ROADMAP.md) as a follow-up.

Off by default — the operator opt-in is deliberate, RFC 8326 §4 says receivers
SHOULD apply this, not MUST.

SIGHUP hot-applies this field. When the value flips, rustbgpd recomputes
runtime policies for every EBGP peer and forces a policy refresh so
already-Established sessions see (or stop seeing) the implicit chain-tail
rule without a daemon restart. iBGP peers are skipped — the rule never
applied to them in the first place.

Hot-apply is **best-effort with partial-apply semantics**: the daemon's
working config and the peer manager's current config both advance to the
new value even if the refresh fan-out fails for some peers (channel-full,
session wedged, etc.). The value reported by `rustbgpd --diff` and
`rustbgpd --check` therefore always matches what the daemon believes it is
running.
Peers that failed the immediate refresh retry on their next policy edit
through the same `pending_refresh` / `pending_export_apply` carry-forward
plumbing used elsewhere in the reload path; transient failures surface as
`warn!` log lines rather than aborting the whole reload.

The matching initiator-side toggle (`rbgp gshut`) is a runtime gRPC
operation, not a config field; see `docs/OPERATIONS.md` for the operator
workflow.

The `"GRACEFUL_SHUTDOWN"` alias is also accepted everywhere
`match_community` / `set_community_add` / `set_community_remove` parse
community values, so policies can refer to it by name without repeating
`65535:0`.

### `honor_blackhole` — RFC 7999 receiver scoping

When `true`, rustbgpd appends an implicit chain-tail rule on every
EBGP peer's import chain:

```
match community = BLACKHOLE (65535:666) → permit, add BLACKHOLE + NO_ADVERTISE
```

RFC 7999 deliberately requires an explicit operator directive before a router
discards traffic for tagged prefixes. This knob is that directive for the
control-plane scoping behavior rustbgpd can enforce today: it preserves the
`BLACKHOLE` marker and adds `NO_ADVERTISE` at the chain tail so a blackhole
request is not propagated to other peers. RFC 1997 egress enforcement happens
before export policy, so `set_community_remove = ["NO_ADVERTISE"]` cannot make
the scoped route exportable. The post-policy result is checked as well, so a
policy that adds `NO_ADVERTISE` suppresses the modified route instead of
advertising it. Earlier operator denies still short-circuit normally. There
is no per-route escape hatch while the knob is enabled: chain evaluation
accumulates permit modifications, so an earlier operator permit does not
bypass the implicit tail rule, and the added `NO_ADVERTISE` cannot be removed
at export. Deliberately propagating a blackhole request to selected peers
requires leaving `honor_blackhole` off (its default) and scoping the
community in operator policy instead.

By default this does **not** install a kernel discard/null route. To turn
local RTBH enforcement on, set both:

```toml
[global]
honor_blackhole = true
install_blackhole_discard = true
```

The FIB path is conservative. It only considers accepted best routes that
still carry `BLACKHOLE` after import policy, only installs routes learned
from EBGP, and only installs IPv4 `/32` or IPv6 `/128` host routes unless
`allow_blackhole_broad_prefixes = true` is also set. Existing foreign kernel
routes for the same prefix are treated as install failures rather than
overwritten, so operator/static or other-daemon routes are preserved.

Rows that carry rustbgpd's own ownership marker (`proto bgp` + blackhole
type in the main table) are the exception: after an unclean restart the
first reconcile pass **adopts** them (ADR-0079), so a crash leftover keeps
discarding attack traffic instead of blocking re-installation as foreign. A
still-desired prefix re-claims its adopted row silently (status `adopted`);
rows no BGP route re-claims stay visible as `adopted_pending_reap` and are
removed after a 500 s deferral, which makes reaping while BGP is still
reconverging unlikely (the deferral is a time proxy for convergence, not a
convergence signal).
Note this marker is a userspace convention: an operator's manual
`ip route add blackhole ... proto bgp` is indistinguishable from daemon
state and will be adopted, and co-residency with another proto-bgp daemon
(e.g. FRR zebra, which claims the same marker) is unsupported.

`rbgp rib blackholes` shows the current discard status for every
BLACKHOLE-marked best route the daemon has observed: `installed`
(`installed` / `owned` / `adopted` / `adopted_pending_reap`), `rejected`
(`broad_prefix` / `not_ebgp`), or `failed` (`foreign_route_exists`,
`dump_failed`, `remove_failed`, `reap_failed`, or the kernel install
error). The same surface is available as JSON with
`rbgp -j rib blackholes`. Adoption and reaping are counted by
`bgp_blackhole_discard_adopted_total` and
`bgp_blackhole_discard_reaped_total`.
If the reconciler cannot start at all (for example netlink setup failure, or
requesting FIB install on a non-Linux build), the status list is empty and
`bgp_blackhole_discard_kernel_failures_total{action="setup"}` or
`{action="unsupported_platform"}` carries the failure signal.

SIGHUP hot-applies this field with the same best-effort partial-apply
semantics as `honor_graceful_shutdown`: rustbgpd recomputes runtime policies
for EBGP peers, advances the live snapshot, and retries transient per-peer
refresh failures through the existing pending-refresh path.

`install_blackhole_discard`, `allow_blackhole_broad_prefixes`, and the
`honor_blackhole` component of an enabled or requested FIB-discard spawn gate
are startup-only in this slice because the kernel-discard reconciler is
spawned once at daemon boot. A SIGHUP that edits those fields logs an error
and pins the live config snapshot back until restart. When FIB discard is not
configured, `honor_blackhole` remains hot-applied through the peer manager.

The `"BLACKHOLE"` alias is accepted everywhere `match_community`,
`set_community_add`, and `set_community_remove` parse community values, so
policies can refer to it by name without repeating `65535:666`.

### `ebgp_requires_policy` — RFC 8212 explicit policy on eBGP

RFC 8212 makes an eBGP route without an explicit import policy ineligible for
the decision process, and keeps a route without an explicit export policy out
of that peer's Adj-RIB-Out. rustbgpd's historical behavior is permit-all when a
session resolves no policy chain, so the RFC 8212 boundary is an opt-in knob:

```toml
[global]
ebgp_requires_policy = true
```

When it is on, an eBGP session that resolves no explicit operator policy in a
direction runs a reserved internal deny-all chain in that direction instead of
the permit-all default. A missing import policy makes received routes
ineligible; a missing export policy keeps routes out of that peer's
Adj-RIB-Out. The session stays Established and keeps exchanging keepalives and
withdrawals, so the gap is repairable without transport churn.

The two directions are independent — a peer with an import policy and no export
policy denies only on egress. Any of these counts as explicit policy, and a
chain whose configured result is permit-all counts just as much as a filtering
one:

- a non-empty neighbor `import_policy_chain` / `export_policy_chain`;
- a non-empty neighbor inline `import_policy` / `export_policy`;
- an inherited non-empty peer-group named chain or inline policy; or
- a non-empty `[policy] import_chain` / `export_chain`.

The implicit RFC 8326 `GRACEFUL_SHUTDOWN` and RFC 7999 `BLACKHOLE` import
tails never count: they are daemon-supplied receiver behavior, not an operator
import relationship, so enabling `honor_graceful_shutdown` or `honor_blackhole`
does not satisfy the requirement.

Because rustbgpd's policy model is neighbor-wide, one directional verdict covers
every configured and negotiated family on that peer. iBGP sessions are not
affected. A `[[dynamic_neighbors]]` range with `remote_asn = 0` is accept-any,
not AS 0: its accepted children are treated as external for their whole session,
including after the OPEN reveals a peer ASN. Configure an explicit
`remote_asn` on the range or a static neighbor if you need iBGP treatment.

`rfc8212_missing_import_policy` and `rfc8212_missing_export_policy` are
reserved policy names. A `[policy.definitions]` entry or `.rpol` policy using
either is rejected at load, so the reserved chain can never be shadowed and
neighbor status and explain output can attribute it unambiguously.

**Before the daemon runs.** `rustbgpd --check` names every configured eBGP
neighbor or dynamic range lacking explicit policy and names the missing
directions. Dynamic rows also name the prefix, peer group, and fixed or
`any AS`; the knob decides whether a missing direction carries no routes or is
unfiltered. It stays a warning — a permit-all route server is a legitimate
configuration — but a check with warnings summarizes as `config VALID, <n>
WARNINGS — NOT a clean check` rather than `config OK`. The exit code is 0
either way; add `--strict` (see [deployment.md](deployment.md)) to make any
warning exit 1 in a CI or deployment gate. `rbgp config import` sets the knob
in every config it generates,
since it never translates policy; its report says so. Every shipped starter —
both `--init-config` profiles and every config under `examples/` — sets it too
and passes `--check --strict`, so a first run is genuinely clean; where a
starter is permit-all by design it says so in a named chain, because
permit-all by omission is indistinguishable from an oversight.

**Observing it.** Each direction is reported independently — `not_required`
(enforcement off, or iBGP), `present`, `missing`, or `unknown`:

- `rbgp neighbor <addr>` prints an `RFC 8212 Policy` block; `--json` carries
  `rfc8212_import_policy` and `rfc8212_export_policy`.
- `bgp_rfc8212_missing_import_policy{peer}` /
  `bgp_rfc8212_missing_export_policy{peer}` are 0/1 per direction.
- `rbgp doctor` fails `peer.<addr>.rfc8212_policy` for a missing direction.
- `rbgp rib advertised <peer> --explain` reports the reserved export deny as
  the `rfc8212_missing_export_policy` gate, not as `policy_denied`.

`/readyz` stays green: a peer without operator policy is a configuration state
for `doctor` to fail, not evidence the daemon cannot serve traffic.

**Editing policy while enforcement is on.** Ordinary policy edits stay live.
An edit that moves a direction *between* explicit policy and the reserved deny
— a policy-presence transition — is qualified first, because it is only
convergent through a Route Refresh: removing the last explicit import policy
has to re-evaluate routes already accepted into Adj-RIB-In, and adding one has
to ask for the routes the deny refused to retain.

Every affected peer is checked before any peer is modified, and one
unqualified peer rejects the whole edit:

- an Established peer that never negotiated RFC 2918 Route Refresh is
  rejected. Clear the session (`rbgp neighbor clear <addr>`) or let it
  reconnect — it relearns everything under the new chain — then reapply.
- a peer that is down while the RIB still holds its graceful-restart or
  long-lived-graceful-restart stale routes is deferred, so those routes stay
  paired with the verdict they were accepted under. Retry once retention
  expires, or clear the peer to purge them.
- a peer whose session cannot report its state in time is rejected rather than
  guessed at; retry the edit.

A rejection changes nothing: chains, verdicts, routes, and sessions are all
left as they were, and a SIGHUP that hits one halts with the reason and the
target named. If a qualified peer flaps before its Route Refresh is delivered,
the edit fails and its prior chains are restored rather than committing a
verdict nothing converged to.

Export-side presence transitions need no capability: they use the same
actor-fenced export replacement as any other export edit, so removing the last
explicit export policy withdraws what was advertised before the edit reports
success.

The knob is deliberately restart-required rather than hot-applied. Enabling it
flips both directions on every eBGP session at once, and recovering a peer's
Adj-RIB-In afterwards depends on negotiated Route Refresh, so a fleet-wide
transition must not hide inside a SIGHUP. A reload that changes the field logs
an `ERROR`, keeps the running value at the startup value, and reports the
candidate as restart-required; `rustbgpd --diff` and the v1 runtime
configuration transaction both name `[global].ebgp_requires_policy` rather than
only the `[global]` section. The v1 transaction rejects such a candidate outright
instead of persisting or partly adopting it.

---

## `[global.telemetry]`

Required. Configures observability and management endpoints.

| Field             | Type   | Required | Default | Description                        |
|-------------------|--------|----------|---------|------------------------------------|
| `prometheus_addr` | string | no       | --      | `host:port` for Prometheus metrics and HTTP `/livez` / `/readyz` probes (omit to disable) |
| `log_format`      | string | yes      | --      | Log output format (`"json"`)       |

`prometheus_addr`, when present, must be a valid `ip:port` socket address. The
same listener serves `/metrics`, `/livez`, and `/readyz`.

### `[global.telemetry.looking_glass]` (removed)

The in-daemon Birdwatcher-shaped looking glass HTTP server has been removed.
The daemon's durable API is gRPC + `rbgp`; its four status, peer, and
accepted-route endpoints (`/status`, `/protocols/bgp`,
`/routes/protocol/{id}`, `/routes/peer/{peer}`) now live in the maintained
external `examples/birdwatcher-adapter`, which also serves a filtered-route
view (`/routes/filtered/{id}`, from `PolicyService.ListRejectedRoutes` with
structured reject reasons) and a noexport view (`/routes/noexport/{id}`,
best-routes-minus-advertised with each suppression explained by
`RibService.ExplainAdvertisedRoute`). A
config that still sets `[global.telemetry.looking_glass]` fails to load with an
ordinary unknown-field diagnostic. See the adapter README for the endpoint→gRPC
mapping.

gRPC listeners are configured with optional subtables:

### `[global.telemetry.grpc_uds]`

Preferred local-only gRPC transport. Unless this table is declared explicitly
(including `enabled = false` as an opt-out), rustbgpd enables this listener by
default at `<runtime_state_dir>/grpc.sock` — also alongside an explicit
`grpc_tcp` listener, so local `rbgp` access keeps working when TCP is added.

An owner-only socket (no group/world mode bits, e.g. the default `0o600`) with
no `principal` authorizes its clients as the implicit, reserved
`local-operator` principal at operator tier — the socket's filesystem
permissions are the authentication, so no `[security.grpc.roles]` entry is
needed. A greenfield config therefore needs no security block at all for
local operation. Group/world-accessible modes still require an explicit
`principal` plus a matching role entry, and `local-operator` itself is
reserved (rejected in roles and listener `principal` fields).

| Field        | Type   | Required | Default | Description |
|--------------|--------|----------|---------|-------------|
| `enabled`    | bool   | no       | `true`  | Enable this listener when the table is present |
| `path`       | string | no       | `<runtime_state_dir>/grpc.sock` | Absolute Unix socket path |
| `mode`       | u32    | no       | `0o600` | Filesystem mode applied to the socket after bind |
| `access_mode` | string | no      | `"read_write"` | Listener authorization mode: `"read_write"` or `"read_only"` |
| `max_tier`   | string | no       | implied by `access_mode` | ADR-0064 per-method listener cap: `read`, `sensitive_read`, `mutating`, or `operator_only` |
| `token_file` | string | no       | --      | Optional bearer token file for listener auth |
| `principal`  | string | no       | --      | Stable ADR-0064 audit principal label for this UDS listener |

### `[global.telemetry.grpc_tcp]`

Optional TCP gRPC listener. Use this only when you need remote access or
container/network exposure.

| Field        | Type   | Required | Default | Description |
|--------------|--------|----------|---------|-------------|
| `enabled`    | bool   | no       | `true`  | Enable this listener when the table is present |
| `address`    | string | yes*     | --      | `host:port` bind address (`required when enabled = true`) |
| `access_mode` | string | no      | `"read_write"` | Listener authorization mode: `"read_write"` or `"read_only"` |
| `max_tier`   | string | no       | implied by `access_mode` | ADR-0064 per-method listener cap: `read`, `sensitive_read`, `mutating`, or `operator_only` |
| `token_file` | string | no       | --      | Optional bearer token file for listener auth |
| `principal`  | string | no       | --      | Stable ADR-0064 audit principal label for non-mTLS bearer-token listeners |
| `tls_cert_file` | string | no   | --      | PEM-encoded server certificate (mTLS — requires the two siblings below) |
| `tls_key_file`  | string | no   | --      | PEM-encoded server private key |
| `tls_client_ca_file` | string | no | --   | PEM-encoded CA bundle that must sign every client certificate |

**Native gRPC mTLS.** Setting any of `tls_cert_file` / `tls_key_file` /
`tls_client_ca_file` requires *all three* together; a partial config is
rejected at `Config::load`. There is no "TLS-without-mTLS" half-mode by
design. When enabled, the daemon presents the server certificate, requires
every client to present a certificate signed by `tls_client_ca_file`, and
rejects unverified clients at the TLS layer before any gRPC handler runs.
PEM material is pre-flight-validated at config load and `--check` time. SIGHUP
re-reads the bytes behind the three unchanged paths, validates the complete
server identity and client CA for every listener, then atomically publishes one
process-wide credential generation. A malformed or partial rotation leaves the
last-known-good generation active. Changing a path or TLS/auth mode remains
**restart-required** and stays visible as drift until restart.

Native gNMI / OpenConfig telemetry (`gnmi.gNMI`) is registered on TCP only when
this native mTLS config is present. Plaintext or bearer-token-only TCP listeners
serve the native `rustbgpd.v1` API but intentionally do not expose network gNMI;
the UDS listener may serve gNMI as a local-only extension. See
[GNMI.md](GNMI.md) for the supported OpenConfig path subset and `gnmic`
examples.

If either listener subtable is present, at least one gRPC listener must remain
enabled after applying `enabled = false`.

`access_mode = "read_only"` permits query and watch RPCs but rejects mutating
RPCs such as neighbor add/delete, route injection, policy changes, peer-group
changes, shutdown, and MRT trigger requests with `PERMISSION_DENIED`. This is
intended for monitoring or dashboard listeners that should not expose control
plane writes.

**ADR-0064 listener tier caps:** `max_tier` is a per-listener ceiling based on
the checked gRPC method-tier matrix. Calls whose method tier is higher than the
effective listener cap return `PERMISSION_DENIED` before the handler runs, after
bearer-token listeners first authenticate the request so missing or invalid
tokens still return `UNAUTHENTICATED` without exposing tier-cap details. The
field is backwards-compatible with `access_mode`: omitting `max_tier` preserves
the existing `access_mode` behavior, `read_only` implies `sensitive_read`, and
`read_write` implies `operator_only`. When both fields are set, the effective
cap is the stricter of the two, so `access_mode = "read_only"` cannot be
weakened by `max_tier = "operator_only"`.

**Token file lifecycle:** When `token_file` is configured, the file must exist
and contain a non-empty token at daemon startup. SIGHUP re-reads the bytes behind
the unchanged path as part of the all-listener credential generation. New RPCs
on existing HTTP/2 connections use the new token; already-admitted streaming
RPCs continue. Invalid or missing material rejects the whole credential reload.
Changing the path or enabling/disabling token auth remains restart-required.

**ADR-0064 principals:** `principal` gives `grpc_authz` records a stable
operator-controlled identity, and it is
the identity looked up in `[security.grpc.roles]`. On UDS listeners it labels the listener identity
established by filesystem permissions and/or the optional token. On TCP
listeners it is accepted only when `token_file` is configured and native mTLS
is not configured. Native mTLS listeners derive the audit principal from the
peer certificate in ADR-0064 order: first `rustbgpd:`
URI SAN, then email SAN, then Subject CN. If a validated client certificate has
none of those fields, or if the selected value is too long or contains embedded
control characters, the audit
principal falls back to `mtls-unresolved`, which cannot be mapped in
`[security.grpc.roles]` and is therefore denied.

### `[security.grpc]`

ADR-0064 per-method authorization is `"tier"` — the default since v0.24.0
and the only mode since v0.63.0. Tier
mode enforces `[security.grpc.roles]` for the authenticated principal before
the handler runs, in addition to listener `max_tier` caps; a declared
principal without a matching `[security.grpc.roles]` entry fails validation at
startup, while owner-only UDS listeners with no principal need no roles block
at all (implicit `local-operator`). The former `"legacy"` migration mode was
removed at runtime in v0.63.0 and from the typed schema in v0.65. The loader
recognizes only that exact retired value and returns the migration steps.

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `enforcement` | string | no | `"tier"` | ADR-0064 enforcement mode. `"tier"` (default since v0.24.0, the only mode since v0.63.0) enforces per-principal role ceilings in addition to listener `max_tier` caps. The typed schema accepts no other value; exact retired `"legacy"` gets a migration diagnostic |

`[security.grpc.roles]` maps an authenticated principal string to one of the
built-in roles:

| Role | Max tier in `enforcement = "tier"` |
|------|------------------------------------|
| `observer` | `sensitive_read` |
| `automation` | `mutating` |
| `operator` | `operator_only` |

When `enforcement = "tier"` is configured:

- Bearer-token TCP listeners must set both `token_file` and an explicit
  `principal`; the token value itself is never used as an identity. That
  principal must have a matching `[security.grpc.roles]` entry.
- Owner-only UDS listeners (no group/world mode bits) with no `principal`
  authorize as the implicit `local-operator` principal at operator tier — no
  roles entry needed. Group/world-accessible UDS listeners must set an
  explicit `principal` with a matching `[security.grpc.roles]` entry.
- Native mTLS TCP listeners derive the principal from the verified client
  certificate and do not set `grpc_tcp.principal`; the roles table must map
  each expected certificate principal.
- Unauthenticated TCP listeners are rejected at config load.
- Requests from principals absent from `[security.grpc.roles]` fail closed with
  `PERMISSION_DENIED`.

A config that fails these rules is rejected with a single error listing every
detected problem, ending with a minimal copy-pasteable TOML block that fixes
that specific config.

**Default changed to `tier` in v0.24.0.** Upgrading a deployment that
uses TCP listeners, group/world-accessible UDS sockets, or declared
principals without staging the migration first will fail validation at
startup; the error lists every problem and ends with a paste-ready
fix. Deployments
that only use an owner-only UDS socket (including the implicit default)
boot without any staging via the implicit `local-operator` identity.
Already-staged operators see no behavior change.

**`enforcement = "legacy"` was removed in v0.63.0** and left the typed schema
in v0.65. Boot, `--check`, and reload still return its paste-ready migration
diagnostic. Earlier editions of this document projected a
two-minor/90-day floor (≈2026-10-09) as the earliest *eligibility* for
removal; that guidance is superseded — the removal landed earlier as an
explicit owner decision under the project's pre-1.0 alpha stability posture,
once the implicit `local-operator` identity removed the migration burden for
local-only deployments. If an upgrade hits the rejection: local-only configs
delete the whole `[security.grpc]` block; named-principal setups keep the
three-line tier config shown in the rejection message (`enforcement =
"tier"` plus a `[security.grpc.roles]` entry for the listener principal).

The safe migration sequence (run against a pre-upgrade daemon if
possible):

1. Add `[security.grpc.roles]` entries for every expected gRPC principal.
2. Set an explicit `principal` on each bearer-token TCP listener and each
   group/world-accessible UDS listener. Owner-only UDS listeners (including
   the implicit default listener) need nothing: their clients are authorized
   as the implicit `local-operator` principal.
3. For remote TCP, prefer native mTLS so the principal is derived from the
   client certificate; otherwise use `token_file` plus a non-secret
   `principal` label.
4. Run `rustbgpd --check` against the candidate TOML; a config that fails
   the tier rules is rejected with a single error listing every problem and
   a paste-ready fix.
5. Deploy and monitor `grpc_authz` logs/metrics for
   `principal_unmapped` and `role_tier_denied`.

```toml
# The v0.24.0 default — equivalent to omitting [security.grpc]
# entirely on a tier-ready config.
[security.grpc]
enforcement = "tier"

[security.grpc.roles]
"observer-readonly" = "observer"
"automation.example" = "automation"
"operator.example" = "operator"
```

```toml
[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

# Group-accessible socket (0o660): wider than owner-only, so under tier it
# requires an explicit principal with a matching role entry below. An
# owner-only socket (default 0o600) with no principal would instead ride the
# implicit local-operator identity and need neither.
[global.telemetry.grpc_uds]
path = "/var/lib/rustbgpd/grpc.sock"
mode = 0o660
access_mode = "read_write"
principal = "local-admin"

# Under tier a TCP listener must authenticate: bearer token + principal
# (create the token file first) or native mTLS.
[global.telemetry.grpc_tcp]
address = "127.0.0.1:50051"
access_mode = "read_only"
max_tier = "sensitive_read"
token_file = "/etc/rustbgpd/grpc.token"
principal = "observer-readonly"

[security.grpc.roles]
"local-admin" = "operator"
"observer-readonly" = "observer"
```

---

## `[[neighbors]]`

Optional, repeatable. Each entry defines one BGP peer. Omit entirely for a
dynamic-only deployment where peers are added at runtime via gRPC.

The server-side presence-aware `AddNeighborRequest.intent` carrier persists the
same raw `[[neighbors]]` intent described here, then resolves it against the
current peer-group before starting the session. Omitted inheritable fields
retain their unset/inherit semantics across canonical persistence and in the
actor snapshot; canonical TOML may render empty-list sentinels such as
`families = []`. Masked `false`, non-empty family replacement, and an atomic
disabled Add-Path block remain explicit across restart. Requests require the
intent, inner config, and FieldMask; field 1/name `config` are reserved, and
missing components or invalid masks are rejected before mutation.

The bundled `rbgp neighbor add` command sends only the presence-aware wrapper,
including an empty mask when every inheritable option is omitted. Its explicit
`--no-route-server-client`, `--no-per-client-best`, `--no-strict-role`, and
`--no-add-path` forms preserve false overrides; any Add-Path option selects the
complete atomic block. There is no probe or automatic legacy fallback.

| Field                  | Type     | Required | Default | Description                                      |
|------------------------|----------|----------|---------|--------------------------------------------------|
| `address`              | string   | yes      | --      | Peer IP address (IPv4 or IPv6)                   |
| `interface`            | string   | IPv6 link-local only | -- | Interface name for `fe80::/10` / unnumbered peers |
| `remote_asn`           | u32      | yes      | --      | Peer's autonomous system number                  |
| `description`          | string   | no       | --      | Human-readable label (used in logs; defaults to address if absent) |
| `peer_group`           | string   | no       | --      | Named peer-group to inherit transport and policy defaults from      |
| `hold_time`            | u16      | no       | 90      | BGP hold timer in seconds (0 or >= 3)            |
| `min_hold_time`        | u16      | no       | unset   | Minimum hold time accepted from the peer (3..=65535). The effective local `hold_time` must be non-zero and at least this value; a peer proposal of 0 is rejected. |
| `send_hold_time`       | u32      | no       | (auto)  | RFC 9687 send hold timer in seconds: tear the session down when the peer stops draining its TCP socket for this long. 0 disables; non-zero must be > `hold_time`. Default: `max(480, 2 × hold_time)` per RFC 9687 §6 |
| `slow_peer_threshold_pct` | u8    | no       | 50      | Slow-peer detection: backlog threshold as a percentage (1--100) of the outbound writer buffer. The peer is a slow-peer candidate while its buffered outbound updates stay at or above this fraction |
| `slow_peer_duration`   | u32      | no       | 30      | How long (seconds) the backlog must persist above the threshold before the peer is flagged slow (neighbor status flag, warn log, `bgp_peer_slow` metric). 0 disables detection. Purely observational unless `slow_peer_isolation` is set |
| `slow_peer_isolation`  | bool     | no       | false   | Move a flagged-slow peer onto its own per-peer update path so it stops holding back its update-group's shared encode; it regroups automatically when the flag clears. Requires detection (`slow_peer_duration > 0`) |
| `max_prefixes`         | u32      | no       | --      | Maximum prefixes accepted before the peer is torn down and, by default, latched off until explicit enable |
| `max_prefixes_ipv4`    | u32      | no       | --      | Maximum unique IPv4-unicast prefixes accepted before latched teardown. Without Notification GR, Cease/1 carries RFC 4486 AFI/SAFI/bound data; with the N-bit, RFC 8538 Cease/9 encapsulates that complete Cease/1. Enforced independently of `max_prefixes` — each configured bound applies to its own count, the aggregate stays a global backstop (ADR-0108) |
| `max_prefixes_ipv6`    | u32      | no       | --      | IPv6-unicast sibling of `max_prefixes_ipv4` (ADR-0108) |
| `max_prefixes_out_ipv4` | non-zero u32 | no | -- | Maximum distinct IPv4-unicast prefixes advertised **to** this peer (ADR-0113). Excess net-new prefixes are withheld while the session stays Established; nothing already advertised is withdrawn and no NOTIFICATION is sent. Counts prefixes, not paths: every Add-Path identity for one NLRI shares a slot |
| `max_prefixes_out_ipv6` | non-zero u32 | no | -- | IPv6-unicast sibling of `max_prefixes_out_ipv4` (ADR-0113) |
| `max_prefix_restart_seconds` | non-zero u32 | no | unset | Opt in to one timed restart attempt after max-prefix teardown. Omit to retain the indefinite fail-closed latch until explicit enable; failure to deliver the timed session `Start` command consumes the attempt and stays latched off |
| `md5_password`         | string   | no       | --      | TCP MD5 authentication password (RFC 2385, Linux only) |
| `tcp_ao`               | table or array | no | -- | Ordered TCP-AO keyring for static neighbors (RFC 5925; Linux; append a non-preferred successor, then select it in a later observation-gated SIGHUP generation) |
| `bfd`                  | table    | no       | --      | Single-hop BFD attachment referencing a `[[bfd_profiles]]` entry (RFC 5880/5881/5882; static neighbors only, restart-required edits) |
| `ttl_security`         | bool     | no       | false   | Enable GTSM / TTL security (RFC 5082, Linux only). Strict: inbound packets must arrive with TTL/Hop-Limit exactly 255 (`IP_MINTTL` / `IPV6_MINHOPCOUNT`, RFC 5082 §3.2) and outbound packets are sent with 255. Earlier releases accepted 254; a peer that depended on that leniency will not establish |
| `families`             | [string] | no       | (auto)  | Address families to negotiate (see below)        |
| `required_families`    | [string] | no       | `[]`    | Families that must appear in the final negotiated intersection; must be a subset of effective `families` |
| `graceful_restart`     | bool     | no       | true    | Enable Graceful Restart receiving speaker (RFC 4724) |
| `gr_restart_time`      | u16      | no       | 120     | Restart time advertised in GR capability (seconds, 1--4095) |
| `gr_peer_restart_time_max` | u16  | no       | 4095    | Local upper bound on the peer-advertised Restart Time used for initial disconnected stale-route retention (seconds, 1--4095); does not change this daemon's OPEN |
| `gr_stale_routes_time` | u64      | no       | 360     | Time to retain stale routes after peer reconnects (seconds, 1--3600) |
| `route_server_client`  | bool     | no       | false   | Transparent route-server mode for eBGP peers (see below) |
| `per_client_best`      | bool     | no       | false   | RFC 7947 §2.3.2 per-client best-path for route-server clients: when export policy denies the Loc-RIB best toward this peer, advertise the best *permitted* candidate instead of hiding the prefix. Requires `route_server_client = true`; inherits from the peer-group (see below) |
| `next_hop_ownership`   | string   | no       | --      | ADR-0107 pre-policy NEXT_HOP ownership enforcement for route-server clients (RFC 7948 §4.8). `"strict_peer"` accepts a unicast announcement only when its complete wire next-hop identity is the advertising session's own address; non-conforming announcements are rejected before import policy (fail-closed, treat-as-withdraw). Requires `route_server_client = true`; inherits from the peer-group (see below) |
| `interpret_rfc1997`    | bool     | no       | (derived) | Honor RFC 1997 `NO_EXPORT`/`NO_EXPORT_SUBCONFED` at egress: routes received with either community are not advertised to this neighbor when it is eBGP. Default: `true` unless `route_server_client = true` (route servers pass communities through transparently and let members enforce them). Inherits from the peer-group; set explicitly to override either default (see below) |
| `rs_control_communities` | bool   | no       | (derived) | Interpret RFC 7947 §2.3.2 / RFC 8195 route-server control communities set by this member: per-target announce suppression, announce-only overrides, and prepend toward a target, keyed on the *target* peer's ASN. Acted-on control communities are scrubbed from this session's outbound announcements. Default: `true` when `route_server_client = true`, `false` otherwise. Inherits from the peer-group; set explicitly to override either default (see below) |
| `role`                 | string   | no       | --      | Local BGP Role for RFC 9234 route-leak protection: `"provider"`, `"rs"`, `"rs-client"`, `"customer"`, or `"peer"` (eBGP only) |
| `strict_role`          | bool     | no       | false   | Require the peer to advertise a compatible BGP Role capability; only valid when `role` is set |
| `prefix_orf_receive`   | bool     | no       | false   | Advertise receive-side Address-Prefix ORF (RFC 5291/5292); peer-pushed prefix filters constrain outbound advertisements |
| `disable_ipv4_unicast` | bool     | no       | false   | True IPv6-only peering: never negotiate IPv4 unicast on this session (suppresses the RFC 4760 §8 implicit-IPv4 fallback; see below) |
| `remove_private_as`   | string   | no       | --      | Remove private ASNs from AS_PATH: `"remove"`, `"all"`, or `"replace"` (eBGP only) |
| `route_reflector_client` | bool   | no       | false   | Mark this iBGP peer as a route reflector client (RFC 4456) |
| `orr_vantage`          | string   | no       | --      | RFC 9107 Optimal Route Reflection IGP location: an IP identifying a node in the BGP-LS-sourced topology; this client's best paths use the interior-cost tiebreak from that node's SPF. Requires `route_reflector_client = true` + iBGP; inherits from the peer-group; an unresolved vantage falls back silently to the standard best (see `rbgp orr`). ADR-0095 |
| `local_ipv6_nexthop`   | string   | no       | --      | Override IPv6 next-hop for eBGP exports (must be valid non-link-local IPv6) |
| `import_policy_chain`  | [string] | no       | --      | Named policy chain for import (mutually exclusive with inline import_policy) |
| `export_policy_chain`  | [string] | no       | --      | Named policy chain for export (mutually exclusive with inline export_policy) |
| `llgr_stale_time`      | u32      | no       | 0       | LLGR stale time in seconds (0 = disabled, max 16777215; RFC 9494)    |
| `add_path`             | table    | no       | --      | Add-Path (RFC 7911) config table (see below)                         |
| `log_level`            | string   | no       | --      | Override log level for this peer: `"error"`, `"warn"`, `"info"`, `"debug"`, or `"trace"` |

Use `rbgp neighbor <addr>` to inspect the actor's current aggregate
max-prefix-counted NLRI identity count and unique IPv4- and IPv6-unicast prefix
counts alongside each effective finite limit and remaining headroom. The
aggregate includes every NLRI family covered by `max_prefixes`; the two family
counts are unicast-only. Human output
prints `unlimited` when a limit is absent, while JSON and gRPC preserve that
state as field absence rather than a synthetic zero. A stale neighbor snapshot
withholds headroom because its zero count is only a placeholder.

`max_prefix_restart_seconds` is inheritable and hot-applied. Changing it while
a hold-down countdown is armed reschedules that one pending attempt to
`now + new duration`; removing it cancels the countdown. Adding a duration to
an already-indefinite latch, or editing it after a `Start` delivery failure
consumed its one chance, does not retroactively arm another attempt. Before an
explicit enable, inspect `rbgp neighbor <addr>`:
`Max-Prefix Action: restart` plus
`Max-Prefix Hold-Down: ... remaining` means the countdown is active. JSON
exposes the same distinction through `max_prefix_action` and
`max_prefix_restart_remaining_millis`. Failure to deliver the automatic
session `Start` command reports `shutdown`, no remaining countdown, and an
actionable `last_error`. Successful delivery clears the latch and returns the
session to ordinary TCP/OPEN retry; it does not assert that establishment
already succeeded.

`max_prefixes_out_ipv4` / `max_prefixes_out_ipv6` are the outbound mirror:
they bound what a bad export policy can grow one client's advertised table
to. Only IPv4- and IPv6-unicast are in scope; VPN, labeled unicast, FlowSpec,
EVPN, BGP-LS, and RT-Constrain are neither counted nor gated. There is one
action — withhold excess net-new prefixes — and no warning-only, restart, or
disable mode.

The same `rbgp neighbor <addr>` output reports one row per unicast family with
its admitted prefix count, effective maximum, remaining headroom, and whether
a blocking episode is open (stable reason `outbound_prefix_limit_reached`).
Usage is the post-policy, post-OTC, post-exact-export admitted count and
agrees with `rbgp rib advertised <addr>`. Prometheus exposes the
same truth as `bgp_outbound_prefix_usage`, `bgp_outbound_prefix_limit`,
`bgp_outbound_prefix_headroom`, and `bgp_outbound_prefix_blocking`, plus the
`bgp_outbound_prefix_blocked_total` attempt counter — all labelled by peer and
family only. An episode logs once when it opens and once when a recovery
resync proves nothing is still withheld, never per prefix.

Edits are live and never reset the session, but they are transactional:
raising or removing a maximum schedules one coalesced resync of just that peer
and family, while adding or lowering one is accepted only when every affected
live peer — static or accepted dynamic, evaluated by effective value after
peer-group inheritance — is already at or below the candidate. An over-limit
family rejects the whole edit and names the peer, family, current usage, and
requested maximum. Reduce the export policy or withdraw routes first; the knob
is not a pruning tool. Commit-confirmed transactions may only tighten, because
their automatic undo can only loosen.

A maximum edited on a `[[neighbors]]` row applies in place: the session task,
its TCP connection, and the FSM are untouched. Editing one on a
`[peer_groups.*]` table keeps that property, because a maximum is a
reload-matrix `live` field and a group edit whose every changed field is `live`
is applied in place to each inheriting member, static and dynamic. A group edit
that also moves a session-reset field still reshapes the group's static members
(ADR-0081); set the maximum on the member's neighbor row if such an edit has to
be made without rebuilding its sessions.

IPv6 link-local neighbors (`fe80::/10`) must set `interface`, because a
link-local address is not globally unique (RFC 4007). Numbered IPv4 / IPv6
neighbors must not set `interface`. Duplicate numbered peers are rejected by
address. In this release each link-local address must also be unique across
neighbors: the same link-local address may not be bound to more than one
interface, because the RIB still keys peers by address. Scoped multi-interface
link-local peering is deferred (see ADR-0069).

```toml
[[neighbors]]
address = "fe80::5054:ff:fe00:1"
interface = "eth1"
remote_asn = 65101
families = ["ipv4_unicast"]
```

TCP-AO (RFC 5925) `tcp_ao` is accepted directly on static `[[neighbors]]` and
on `[[dynamic_neighbors]]` ranges. It is an ordered keyring containing
one to 256 Master Key Tuples (MKTs). The legacy singleton table remains valid
and is also the canonical serialized shape for a one-key ring. Configure two or
more keys as an ordered array of inline tables.

On Linux, rustbgpd installs every configured key on outbound active-open
sockets before `connect()` and on the passive BGP listener before `listen()`
when the peer address family matches the configured listener socket. If any
listener key cannot be installed, startup fails closed instead of running a
partially protected listener. Any active-open installation or kernel-inventory
reconciliation failure fails that session connect attempt and retries later;
it never falls back to an unauthenticated session. `rbgp global` /
`GlobalService.GetGlobal` expose the host capability probe so operators can
verify kernel support before enabling the field.

Exactly one non-deprecated key is selected for startup transmission: the key
marked `preferred`, or the first declared non-deprecated key if none is marked.
Active-open sockets install that selected key first as Linux `current_key` and
`rnext_key` so the initial SYN is signed, then install the remaining MKTs in
declaration order. Listener sockets install every MKT in declaration order
without `current_key` / `rnext_key`; Linux rejects those flags on listening
sockets. After accept, rustbgpd preserves the peer-selected current key, sets
the receive-next key to the locally selected key's `recv_id`, and reconciles
the complete configured keyring. rustbgpd does not set the socket-wide
`ao_required` bit because a shared BGP listener may also serve non-TCP-AO
neighbors.

Passive-open ownership is deterministic: an exact static neighbor takes
precedence over every dynamic selector; otherwise the longest matching dynamic
prefix owns the session (including dynamic `/32` and `/128` selectors). Because
Linux may inherit MKTs from every protected selector covering an accepted peer,
rustbgpd verifies the configured union of all such owners while requiring the
current and RNext selection to belong to the resolved owner. Overlapping
TCP-AO owners must have pairwise-disjoint SendID sets and pairwise-disjoint
RecvID sets. Any overlap between TCP-AO and plaintext or MD5 configuration is
rejected. Across all static and dynamic owners, each address family may install
at most 4,096 listener MKTs; larger configurations are rejected before listener
startup so accepted-socket inventory inspection remains complete.

Linux TCP-AO MKTs are socket state. On SIGHUP, rustbgpd can live-install a
strict add-only successor generation when every protected static and dynamic
owner is unchanged, every existing key remains byte-for-byte in declaration
order, and every appended key has `preferred = false`. The daemon globally
preflights capacity and every managed protected session, adds keys without
changing Current/RNext, verifies the complete listener and connected-socket
inventories, and generation-fences newly accepted protected sockets until all
managed sessions converge. A child that completed in the kernel accept queue
before the listener flip still has the exact immediately previous inventory;
rustbgpd adds only that generation's missing suffix, requires an exact final
current inventory, and then stamps the current generation. Arbitrary subsets,
partial successor inventories, and children older than the immediate previous
generation are rejected.

After that successor is installed everywhere, a later SIGHUP may select it as
local RNext and mark its predecessor deprecated in one immutable generation.
The reload must keep the exact owner union, MKT order, keys, IDs, and
algorithms; adding and selecting in the same generation is rejected. Selection
never sets Linux Current. The daemon captures the successor's per-key
`pkt_good` immediately before setting RNext, performs one observation pass, and
commits final deprecation metadata only after every affected protected session reports
the successor as both Current and RNext with `pkt_good` strictly above that
baseline and all authentication error counters still zero. If a peer is not
ready, status remains `awaiting_peer` with `desired=N`, `applied=N-1`; a later
SIGHUP must carry the identical full desired config and retries the same N.
There is no actor-side polling. After that selection/deprecation generation
commits, a later SIGHUP may remove one or more deprecated MKTs that are neither
Current nor RNext on any affected listener, queued child, primary session, or
pending session. The survivor keyring must be nonempty and preserve the exact
owner set, declaration order, key definitions, and selected MKT. Editing,
reordering, or moving a key, deleting a non-deprecated or selected key, or
changing a protected owner remains restart-required and pinned.

If a live TCP-AO generation fails before listener mutation, after an exact
prior-inventory restoration, or after the listener already reached the desired
inventory, the same immutable desired generation is retryable with another
SIGHUP. Some successor MKTs may already be present; retries accept them only
when their kernel-normalized key material is identical. If partial listener
deletion cannot restore the exact prior inventory, a retry must re-prove that
exact inventory before another mutation; otherwise it is rejected and the
daemon must be restarted. An intermediate kernel subset is not a resumable
generation. Affected protected passive accepts may reject until an eligible
retry or restart, and a fully installed but globally uncommitted generation
remains fenced. A deletion that
may have changed any protected session closes the whole
changed session cohort before reporting failure; failure to reset every affected
task aborts them all. Established sessions otherwise retain their prior
selectable keys. Inspect per-neighbor
`tcp_ao_desired_generation`, `tcp_ao_applied_generation`,
`tcp_ao_rotation_phase`, and `tcp_ao_rotation_error` in JSON, or the equivalent
`TCP-AO Rotation` rows in human output.

`tcp_ao` is mutually exclusive with `md5_password`, including an inherited
peer-group MD5 password. It is not available in `[peer_groups.*]`; dynamic
ranges configure their prefix keyring directly. The legacy singleton form is:

```toml
[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
tcp_ao = {
  key = "secret",
  send_id = 1,
  recv_id = 1,
  algorithm = "hmac(sha256)",
  preferred = true,
  deprecated = false,
}
```

A two-key rollover can be staged as an ordered array. First append the
non-preferred successor with SIGHUP; after that generation commits, make the
successor preferred and the predecessor deprecated, then SIGHUP again:

```toml
[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
tcp_ao = [
  { key = "old-secret", send_id = 1, recv_id = 11, algorithm = "hmac(sha256)", deprecated = true },
  { key = "next-secret", send_id = 2, recv_id = 12, algorithm = "hmac(sha256)", preferred = true },
]
```

Allowed `algorithm` values are `"hmac(sha1)"`, `"hmac(sha256)"`, and
`"cmac(aes128)"`. `key` must be 1--80 bytes. `send_id` and `recv_id` are
TCP-AO KeyIDs (`0..=255`). They are directional: this neighbor's `send_id`
must equal the peer's `recv_id`, and this neighbor's `recv_id` must equal the
peer's `send_id`. For the example above, the peer must therefore configure
RecvIDs 1 and 2, and SendIDs 11 and 12, for the corresponding secrets.

Within one keyring, every `send_id` must be unique and every `recv_id` must be
unique. At most one entry may be `preferred`; a preferred key cannot also be
`deprecated`; and at least one entry must be non-deprecated. If there is no
preferred entry, declaration order is significant because the first
non-deprecated key is selected. Reordering is therefore a restart-required
configuration change. Appending a non-preferred successor can be installed
live on SIGHUP; a later SIGHUP can select that installed successor and
observation-gate predecessor deprecation in the same immutable generation.
Deleting an MKT remains restart-coordinated.

### BFD (RFC 5880 / 5881 / 5882)

Single-hop asynchronous BFD (ADR-0067) gives sub-second peer-failure detection
and, via RFC 5882, tears the BGP session down on a BFD-down event before the
hold timer expires. Timers live in named profiles; neighbors (or peer groups)
attach to a profile.

```toml
# A named timing profile. Intervals are milliseconds.
[[bfd_profiles]]
name = "fast"
min_tx_interval = 300   # default 300, floor 100
min_rx_interval = 300   # default 300, floor 100
multiplier = 3          # default 3, min 2 (detection ≈ interval × multiplier)

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
# Attach BFD. `strict` is optional (default false).
bfd = { profile = "fast" }

# Peer groups can carry a default; a neighbor can override it off:
[peer_groups.edge]
bfd = { profile = "fast" }

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
peer_group = "edge"
bfd = { profile = "fast", enabled = false }   # opt this neighbor out
```

`[neighbors.bfd]` / `[peer_groups.<name>.bfd]` fields:

| Field     | Type   | Default | Description                                                       |
|-----------|--------|---------|-------------------------------------------------------------------|
| `profile` | string | --      | Name of a `[[bfd_profiles]]` entry (must exist)                   |
| `enabled` | bool   | true    | Set `false` to disable BFD (e.g. override an inherited group block) |
| `strict`  | bool   | false   | RFC 5882 strict mode: withhold BGP establishment until BFD is Up   |

In **non-strict** mode (default) BGP establishes normally and a later BFD-down
tears it down faster than the hold timer; recovery re-establishes. In **strict**
mode the BGP session is withheld (on both the active-open and inbound paths)
until BFD first reaches Up.

A **remote `AdminDown`** — the peer *administratively disabling* BFD — is treated
per RFC 5882 §4.1 as administrative, not a liveness failure: the BGP adjacency is
**allowed in both modes**. An established session stays up; a withheld strict
session is released. (BGP keeps its own hold-timer liveness; BFD is simply not in
use while the peer has it administratively down. Our local BFD session state
stays `Down` in this case — the remote-AdminDown cause is tracked separately — so
`GetBfdSessions` still shows `Down` and reports
`remote_administrative_down = true`; the BGP coupling uses that cause to permit
BGP.) Genuine failures — a detection timeout or a remote-signaled
`Down` — still tear BGP down (non-strict) or keep it withheld (strict). A *local*
operator disable/delete of the neighbor stops BGP through the normal lifecycle,
not this path.

BFD is **static-neighbors only** in v1 — a `[[dynamic_neighbors]]` range whose
peer group enables BFD is rejected at config time. v1 covers IPv4 + IPv6
**global** addresses. BFD on IPv6 link-local / unnumbered peers is still
deferred even though the BGP neighbor itself can be interface scoped. Like
TCP-AO, BFD edits are **restart-required**: on SIGHUP rustbgpd pins
`[[bfd_profiles]]` and neighbor / peer-group `bfd` back to the live snapshot and
reports them as restart-required in `--diff`. Inspect sessions with
`rbgp bfd` / `BfdService.GetBfdSessions` (see [API.md](API.md)); an older daemon
that omits the optional cause field is shown explicitly as unknown rather than
silently treated as a genuine failure.

### Address families

The `families` field controls which AFI/SAFI combinations are negotiated with
the peer via MP-BGP capabilities. Supported values:

- `"ipv4_unicast"` — IPv4 Unicast (AFI 1, SAFI 1)
- `"ipv6_unicast"` — IPv6 Unicast (AFI 2, SAFI 1)
- `"ipv4_flowspec"` — IPv4 FlowSpec (AFI 1, SAFI 133, RFC 8955)
- `"ipv6_flowspec"` — IPv6 FlowSpec (AFI 2, SAFI 133, RFC 8956)
- `"linkstate"` — BGP-LS (AFI 16388, SAFI 71, RFC 9552). Learned BGP-LS
  routes are stored in the RIB, exposed through `RibService.ListBgpLsRoutes` /
  `rbgp rib bgpls`, reflected to eligible negotiated peers, and can feed RFC
  9107 ORR topology. rustbgpd does not originate local BGP-LS objects or
  negotiate BGP-LS Add-Path. GR / LLGR stale preservation for BGP-LS and
  BGP-LS VPN is implemented through the RR-family stale pipeline.
- `"linkstate_vpn"` — BGP-LS VPN (AFI 16388, SAFI 72, RFC 9552), with
  the same controller-feed / reflection scope as `linkstate`.
- `"l2vpn_evpn"` — L2VPN EVPN (AFI 25, SAFI 70, RFC 7432). Two
  deployment modes share the family:
  - **RR mode (Phase 1):** the daemon reflects all five RFC 7432
    route types between iBGP-speaking VTEPs configured as
    `route_reflector_client = true`, with no local EVI state. Empty
    `[[evpn_instances]]` selects this mode.
  - **Bidirectional VTEP mode (Phase 2 — Gates 7a / 7b / 7b+1 / 7b+2 / 7c / 8 / 8b):**
    populating `[[evpn_instances]]` (see § *EVPN VTEP instances*
    below) makes the daemon program remote-MAC FDB entries from
    received Type 2 routes (downward), originate local MAC-only and
    MAC+IP Type 2 routes plus one Type 3 IMET per L2VNI (upward),
    and optionally run Gate 8/8b multi-homing enforcement when
    `[[ethernet_segments]]` and `apply_bum_enforcement` are
    configured. Linux-only; requires `CAP_NET_ADMIN` for the
    rtnetlink subscription and FDB program path.
  See [docs/USE_CASES.md](USE_CASES.md) § "VXLAN-EVPN DC Fabric"
  for a worked example and `examples/rr-evpn-fabric/config.toml`
  for a copy-paste-ready starting point.
- `"l3vpn_ipv4_unicast"` — VPNv4 (AFI 1, SAFI 128, RFC 4364)
- `"l3vpn_ipv6_unicast"` — VPNv6 (AFI 2, SAFI 128, RFC 4659)

  Both ship as a route-reflector / controller-feed slice: receive, store,
  reflect, and withdraw with RD / MPLS label stack / next-hop / Route
  Targets preserved verbatim, plus the RFC 8277 §2.4 withdraw codec and
  Enhanced Route Refresh stale lifecycle. No VRF import, label allocation,
  or MPLS FIB (deliberate — see [docs/gobgp-parity.md](gobgp-parity.md)).
- `"ipv4_labeled_unicast"` — IPv4 labeled-unicast (AFI 1, SAFI 4, RFC 8277)
- `"ipv6_labeled_unicast"` — IPv6 labeled-unicast (AFI 2, SAFI 4, RFC 8277)
- `"rtc"` — Route Target Constrain (AFI 1, SAFI 132, RFC 4684). Strict
  per-peer VPN reflection filtering: a negotiated peer with empty RTC
  interest receives nothing, with RFC-faithful 96-bit prefix matching.

**Defaults:** If `families` is omitted, the default depends on the neighbor
address type:

- IPv4 neighbor address → `["ipv4_unicast"]`
- IPv6 neighbor address → `["ipv4_unicast", "ipv6_unicast"]`

Set `required_families` when partial negotiation is unsafe for a particular
session. The list defaults to empty, preserving ordinary RFC 4760 partial
intersection. A non-empty neighbor list overrides the peer-group list; an
empty or omitted neighbor list inherits a non-empty group list (an explicit
empty list cannot clear it). Every required family must remain in the effective
configured set after `disable_ipv4_unicast` is applied. If the peer's OPEN does
not negotiate every required family, rustbgpd sends OPEN Message Error /
Unsupported Capability (2/7); Data contains only the missing six-byte
MultiProtocol capability TLVs, in configured order. Capability-less legacy
IPv4 peers still satisfy a required `ipv4_unicast` through RFC 4760 §8.

```toml
[peer_groups.dual-stack]
families = ["ipv4_unicast", "ipv6_unicast"]
required_families = ["ipv6_unicast"]
```

### IPv6-only peering (`disable_ipv4_unicast`)

Per RFC 4760 §8, IPv4 unicast is implicitly available on a BGP session
whenever it is not explicitly negotiated away — even a `families =
["ipv6_unicast"]` neighbor still ends up with IPv4 unicast negotiated.
That default is correct for backward compatibility but wrong for an
IPv6-only fabric (including ADR-0069 link-local unnumbered peering)
where the peer genuinely refuses IPv4 unicast.

Set `disable_ipv4_unicast = true` on a neighbor or peer group to make
the session truly IPv6-only:

- IPv4 unicast is excluded from the MultiProtocol capability rustbgpd
  advertises in OPEN (and from every family-derived capability: GR,
  LLGR, Add-Path, ORF, extended next-hop), regardless of what
  `families` resolves to.
- The RFC 4760 §8 implicit-IPv4 fallback is suppressed during
  negotiation — IPv4 unicast is never added behind the operator's back.
- If the resulting family intersection with the peer is empty (for
  example the peer advertises only IPv4 unicast, or sends no
  MultiProtocol capability at all), rustbgpd rejects the session with
  NOTIFICATION OPEN error / Unsupported Capability (2/7) — the same
  behavior FRR exhibits when configured AFI/SAFIs do not overlap.

```toml
[[neighbors]]
address = "fd00:64::2"
remote_asn = 65002
families = ["ipv6_unicast"]
disable_ipv4_unicast = true
```

Config validation rejects `disable_ipv4_unicast = true` when the
neighbor's effective `families` resolve to `ipv4_unicast` only — that
combination could never negotiate anything. The knob is off by default;
existing configs behave identically. It controls capability negotiation
only: RFC 8950 extended-next-hop and unnumbered peering are unaffected.

### Peer groups

Peer groups are reusable neighbor templates defined at the top level under
`[peer_groups.<name>]`. A neighbor can reference one with `peer_group = "..."`.
Explicit neighbor settings win over peer-group settings. Peer-group definitions
can also be managed at runtime through the gRPC `PeerGroupService`; successful
mutations persist back to TOML.

```toml
[peer_groups.rs-clients]
hold_time = 90
min_hold_time = 30
families = ["ipv4_unicast", "ipv6_unicast"]
required_families = ["ipv6_unicast"]
route_server_client = true
export_policy_chain = ["tag-ixp"]

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
peer_group = "rs-clients"

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
peer_group = "rs-clients"
hold_time = 45  # neighbor override beats peer-group default
```

Peer-group fields mirror inheritable neighbor settings: timers, families,
prefix limits (`max_prefixes`, `max_prefixes_ipv4`, `max_prefixes_ipv6`,
`max_prefixes_out_ipv4`, `max_prefixes_out_ipv6`) and
`max_prefix_restart_seconds`,
GR/LLGR, Add-Path, route-server / RR flags, BGP Role / strict-role defaults,
receive-side Prefix ORF, private-AS handling, MD5/GTSM,
`local_ipv6_nexthop`, `log_level`, slow-peer detection
(`slow_peer_threshold_pct`, `slow_peer_duration`, `slow_peer_isolation`),
and import/export inline policy or named chains. TCP-AO is intentionally not inherited through peer groups; static
neighbors and dynamic ranges configure their startup key directly.

```toml
# IPv4 peer with dual-stack
[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
description = "upstream-provider"
hold_time = 90
max_prefixes = 10000
# Optional: make one restart attempt 300 seconds after a max-prefix breach.
# Omit this to require an explicit `rbgp neighbor <addr> enable`.
max_prefix_restart_seconds = 300
md5_password = "s3cret"
ttl_security = true
families = ["ipv4_unicast", "ipv6_unicast"]

# IPv6 peer (defaults to dual-stack)
[[neighbors]]
address = "fd00::2"
remote_asn = 65003
description = "ipv6-peer"
```

**Extended Next Hop (RFC 8950):** When both `"ipv4_unicast"` and
`"ipv6_unicast"` are configured for a neighbor, rustbgpd automatically
advertises the Extended Next Hop capability. If negotiated, IPv4 unicast
routes may be exchanged via `MP_REACH_NLRI` / `MP_UNREACH_NLRI` using an
IPv6 next hop. For eBGP exports, `local_ipv6_nexthop` (if configured) is
used as the IPv6 self next-hop; otherwise the local IPv6 socket address is
used when available.

---

## `[[dynamic_neighbors]]`

Optional, repeatable. Defines prefix ranges for auto-accepting inbound BGP
connections. When an inbound TCP connection arrives from an address inside the
configured prefix, rustbgpd creates an ephemeral peer using the referenced peer
group.

Dynamic peers:

- inherit transport and policy defaults from the referenced peer group
- never initiate outbound TCP connections
- the ephemeral peer entry is not written back to `[[neighbors]]` (the *range*,
  however, is persisted to `[[dynamic_neighbors]]` when added at runtime — see
  "Runtime management" below)
- the ephemeral peer is removed automatically when its session returns to Idle
  (the range itself persists)
- count against `global.dynamic_neighbor_limit`

| Field         | Type   | Required | Default | Description |
|---------------|--------|----------|---------|-------------|
| `prefix`      | string | yes      | --      | IPv4 or IPv6 prefix range in CIDR notation |
| `peer_group`  | string | yes      | --      | Peer group whose settings dynamic peers inherit |
| `remote_asn`  | u32    | no       | `0`     | Expected remote ASN. `0` means accept any ASN from the peer's OPEN |
| `description` | string | no       | --      | Optional description applied to accepted dynamic peers |
| `tcp_ao`      | table or array | no | -- | Direct ordered TCP-AO prefix keyring; Linux; append a non-preferred successor, then select it in a later observation-gated SIGHUP generation |

When `remote_asn = 0`, the accepted peer keeps the configured range as
accept-any, but the ephemeral peer's session state uses the ASN learned from the
peer's OPEN. Peer snapshots, gRPC state, BMP peer state, and RIB peer-up
metadata therefore report the learned ASN rather than the sentinel `0`.
For operator attribution, live dynamic-peer snapshots also retain the
canonical prefix and peer group that accepted the connection. That captured
provenance does not change if a more-specific range is later removed while the
session remains established; it is not recomputed from the current
longest-prefix matcher.

```toml
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
dynamic_neighbor_limit = 500

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[peer_groups.ix-members]
hold_time = 90
families = ["ipv4_unicast", "ipv6_unicast"]
route_server_client = true

[[dynamic_neighbors]]
prefix = "10.0.0.0/24"
peer_group = "ix-members"
remote_asn = 0
description = "IXP auto-accept"
tcp_ao = { key = "secret", send_id = 1, recv_id = 1, algorithm = "hmac(sha256)" }

[[dynamic_neighbors]]
prefix = "2001:db8::/32"
peer_group = "ix-members"
```

Validation rules:

- `peer_group` must reference an existing `[peer_groups.<name>]`
- `prefix` must be valid CIDR with a family-appropriate prefix length
- static `[[neighbors]]` cannot use `remote_asn = 0`; that sentinel is reserved for `[[dynamic_neighbors]]`
- inherited RR/ORR settings require a fixed local-AS `remote_asn`; wildcard
  `0` is external and cannot form an iBGP route-reflector session
- inherited route-server mode and BGP Roles require eBGP (`0` remains valid);
  `per_client_best` and `next_hop_ownership` require route-server mode, while
  `strict_role` requires a role
- two ranges covering the **identical** effective prefix (same masked network
  and length) are rejected; overlapping ranges of *different* lengths are
  allowed and resolve by longest-prefix-match at accept time
- a TCP-AO-protected range must satisfy the TCP-AO keyring validation above;
  static exact ownership precedes dynamic longest-prefix-match; every covering
  protected owner's keyring is reconciled as one inherited union; overlapping
  protected owners require disjoint SendID and RecvID sets; TCP-AO/plaintext or
  TCP-AO/MD5 overlaps are rejected; and its peer group must not configure MD5
- static and dynamic TCP-AO keyrings may contain at most 4,096 listener MKTs
  per address family in aggregate

### Runtime management (gRPC / `rbgp`)

Ranges can be added and removed at runtime without a restart, in addition to
the static TOML form above:

```sh
rbgp dynamic-neighbor list
rbgp dynamic-neighbor add 10.0.0.0/24 --peer-group ix-members [--remote-asn 65010] [--description "..."]
rbgp dynamic-neighbor delete 10.0.0.0/24
```

- Backed by `NeighborService` (`AddDynamicNeighbor` / `DeleteDynamicNeighbor` /
  `ListDynamicNeighbors`); add/delete are tier `mutating`.
- Runtime changes reserve config persistence capacity before mutating and then
  wait for the atomic TOML write to be acknowledged after the peer manager
  accepts the change. Runtime dynamic-neighbor CRUD is serialized with SIGHUP
  reload, so a reload sees either the pre-mutation TOML or the committed
  post-mutation TOML. If the write is rejected after the runtime mutation, the
  matcher is rolled back and the RPC reports failure. The write rewrites the
  whole config file in canonical form — see
  [Config Persistence](#config-persistence).
- **Delete stops *future* accepts only.** Already-established dynamic peers from
  a removed range keep running and drain naturally when they next return to
  Idle; delete never tears down a live session.
- Add is rejected for an unknown or BFD-enabled peer group, an invalid prefix,
  or a duplicate effective prefix. Delete matches by effective prefix, so a
  host-bit variant of the same network (e.g. `10.0.0.7/24`) removes the
  `10.0.0.0/24` range.
- Protected ranges cannot be added or deleted through runtime CRUD. Adds that
  overlap a protected range are also rejected; edit TOML and restart instead.

Operational note:

- disabling a dynamic peer keeps the peer entry in memory but prevents reconnect

### Graceful Restart (RFC 4724)

Graceful Restart is enabled by default. rustbgpd implements:

- **Helper mode (receiving speaker):** when a peer with GR capability
  restarts, its routes are preserved as stale during the restart window
  instead of being immediately withdrawn. End-of-RIB markers from the peer
  clear stale flags per address family; if the timer expires before all
  End-of-RIB markers arrive, remaining stale routes are swept.
- **Minimal restarting-speaker mode:** after a coordinated daemon restart,
  rustbgpd can temporarily advertise `restart_state = true` to static peers
  restored from config, using a marker file under `runtime_state_dir`.
  This helps peers retain our routes while we reconnect, but
  `forwarding_preserved` remains false because rustbgpd does not restore routing
  state or verify that forwarding state survived. The optional shutdown warm
  checkpoint is publication-only and does not change that claim.
  ADR-0061 FIB programming is opt-in and scoped; crash-left rows are preserved
  as foreign rather than adopted.

```toml
[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
graceful_restart = true      # default: true
gr_restart_time = 120        # seconds, advertised in GR capability (max 4095)
gr_peer_restart_time_max = 300 # cap the peer's advertised time while disconnected (max 4095)
gr_stale_routes_time = 360   # seconds, how long to wait for EoR after reconnect (max 3600)
```

The three timers are directional and apply at different stages.
`gr_restart_time` is advertised in this daemon's OPEN for peers helping this
daemon restart. `gr_peer_restart_time_max` is not advertised: it caps the
Restart Time received from this peer before rustbgpd starts the initial
disconnected stale-route timer. The default `4095` preserves the full RFC 4724
wire range. After the peer reconnects, `gr_stale_routes_time` bounds the wait
for its per-family End-of-RIB markers. The cap inherits from a peer group and a
neighbor value overrides the group.

To disable GR for a specific peer:

```toml
[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
graceful_restart = false
```

**Implementation note:** restarting-speaker mode is deliberately honest. The
daemon may advertise `R=1` after a planned restart, but it does not claim
forwarding-state preservation (`forwarding_preserved = false`) and never
restores route state from the optional shutdown checkpoint. During that
marker-backed startup it
freezes the effective static GR peer/family roster and defers each family's
route selection plus initial table/EoR until all eligible current sessions
send EoR or the remaining marker window expires. `gr_restart_time` therefore
bounds both the advertised restart window and, via the maximum effective value
across static peers, the process-start selection deferral.

During a same-address collision, ordinary replacement still re-arms the
replacement session as an EoR waiter and stale predecessor EoR is rejected. If
the replacement then loses and registration fails back to the exact nonzero,
unambiguous survivor, only that survivor enters `awaiting_refresh` — and only
when its session negotiated Enhanced Route Refresh for a GR family; a
Restart-State, non-GR, or plain-refresh survivor is excluded instead, because
it can never produce the BoRR/EoRR proof. Other waiters continue to block.
Once ordinary waiters finish, the current Loc-RIB is staged immediately, but
family EoR and route-refresh responses remain held. A post-failback BoRR arms
the waiter and only the matching peer EoRR releases it. An ordinary EoR, stray
EoRR, or local refresh timeout cannot declare convergence. The original
marker-bounded timer remains the overall fallback.

`rbgp neighbor <address>` shows `Selection Deferral` rows while active and
retains their `all_eor`, `collision_refresh`, `all_excluded` (the gate
completed with every waiter excluded or deleted — zero completion markers
consumed), or `timer` release reason afterward. Metrics are
`bgp_selection_deferral_active`, `bgp_selection_deferral_waiters`,
`bgp_selection_deferral_releases_total`, and
`bgp_selection_deferral_timeouts_total`. The process-wide deferred-identity
ledger has two independent limits: one million distinct keys and 64 MiB of
deterministic logical retained-key data. The byte limit counts inline key data,
nested FlowSpec numeric/bitmask terms, and each BGP-LS key payload; it is not a
process-RSS, allocator-capacity, or hash-table-overhead limit. If retaining a
new identity would exceed either process-wide limit, that identity's family
enters overflow fallback and
`bgp_selection_deferral_ledger_overflows_total` increments once for each
affected family and release sweeps the complete Adj-RIB-In plus Loc-RIB family
so an already-withdrawn identity cannot remain stale. All labels are bounded by
configured family and release reason.
See [ADR-0024](adr/0024-graceful-restart.md).

### Long-Lived Graceful Restart (RFC 9494)

LLGR extends Graceful Restart with a second stale-timer phase. When the GR
timer expires, routes for LLGR-negotiated families are promoted to LLGR-stale
(with the `LLGR_STALE` well-known community added) instead of being purged.
Routes carrying `NO_LLGR` are purged at the GR-to-LLGR transition.

The effective LLGR stale time is `min(local llgr_stale_time, peer's per-family minimum)`.

```toml
[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
graceful_restart = true
llgr_stale_time = 3600    # seconds (0 = disabled, max 16777215)
```

To disable LLGR for a specific peer, set `llgr_stale_time = 0` (the default).

Best-path selection uses three-tier stale ranking: fresh > GR-stale > LLGR-stale,
applied at step 0 (before LOCAL_PREF). LLGR-stale routes are least preferred but
still participate in best-path selection until the LLGR timer expires.

See [ADR-0024](adr/0024-graceful-restart.md) for the two-phase timer design.

### Add-Path (RFC 7911)

Add-Path allows accepting and advertising multiple paths per prefix.
Configure it per-neighbor with the `[neighbors.add_path]` table:

```toml
[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002

[neighbors.add_path]
receive = true    # accept multiple paths per prefix from this peer
send = true       # advertise multiple paths per prefix to this peer
send_max = 4      # limit to top 4 candidates (omit for unlimited)
receive_max = 3   # experimental Paths-Limit preference sent to this peer
```

| Field      | Type    | Required | Default | Description                                |
|------------|---------|----------|---------|--------------------------------------------|
| `receive`  | bool    | no       | false   | Accept multiple paths per prefix from peer  |
| `send`     | bool    | no       | false   | Advertise multiple paths per prefix to peer |
| `send_max` | integer | no       | —       | Max paths per prefix (omit for unlimited)   |
| `receive_max` | integer | no    | —       | Experimental preferred maximum received paths per family (1..=65535); omit or set 0 to disable |

When `receive` is true, the Add-Path capability (code 69) is advertised in
OPEN with `Receive` mode. When `send` is true, `Send` mode is advertised.
If both are enabled, `Both` is advertised.

`receive_max` enables the experimental Paths-Limit capability (code 76,
draft-abraitis-idr-addpath-paths-limit-04). rustbgpd advertises the value only
for families where Add-Path receive is enabled. A remote Paths-Limit tuple caps
the corresponding outbound Add-Path family at the smaller of `send_max` and
the peer's value; it does not affect other families and never rejects excess
inbound paths. Zero tuples and tuples without matching Add-Path negotiation are
ignored. Because the draft expired without IETF adoption, deploy this only
after confirming peer support. `rbgp neighbor <address>` reports configured,
advertised, received, and effective values per family in stable numeric
AFI/SAFI order. Effective send renders as `inactive`, `unlimited`, or a finite
cap. JSON pairs `effective_send_active` with optional `effective_send_limit`;
protobuf uses the same encoding: absent is inactive, present zero is active and
unlimited, and present non-zero is active with that finite limit.
Clients that still read the removed raw `effective_send_max` field must upgrade
to the presence-aware field.

**Multi-path send (route server mode):** When `send = true`, the RIB
distributes multiple candidate paths per prefix to this peer, sorted by
best-path preference. Paths are assigned rank-based path IDs (best=1,
second=2, etc.). Split horizon, iBGP suppression, and per-candidate export
policy are evaluated for each path.

Both IPv4 and IPv6 unicast are supported. See [ADR-0033](adr/0033-add-path.md).

### Transparent Route Server Mode

For IX route-server clients, you can make eBGP export transparent by setting
`route_server_client = true` on the neighbor:

```toml
[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
families = ["ipv4_unicast", "ipv6_unicast"]
route_server_client = true
```

When enabled:

- outbound **unicast** advertisements to that peer preserve the original next
  hop by default
- outbound **unicast** advertisements skip the automatic local-AS prepend
  normally applied on eBGP export
- outbound **FlowSpec** advertisements skip the automatic local-AS prepend
- explicit export-policy next-hop rewrites (`set_next_hop`) still win for
  unicast
- `LOCAL_PREF` is still stripped, because the peer is still eBGP

This applies to:

- classic IPv4 unicast (`NEXT_HOP`)
- IPv4 unicast over IPv6 next hop (RFC 8950)
- IPv6 unicast (`MP_REACH_NLRI`)
- IPv4 and IPv6 FlowSpec export (`AS_PATH` transparency only; FlowSpec has no
  wire-level `NEXT_HOP`)

Transparent export does not by itself verify that an inbound unicast next hop
belongs to the advertising route-server client — a next-hop rewrite alone is
not ownership validation. Enable the ownership gate below where members must
not announce third-party next hops.

`route_server_client` is only valid for eBGP neighbors. Config validation
rejects it on iBGP peers.

#### NEXT_HOP ownership enforcement (`next_hop_ownership`, ADR-0107)

RFC 7948 §4.8 describes next-hop hijacking on a shared IXP fabric: a member
announces a route whose `NEXT_HOP` points at another member, blackholing or
intercepting that traffic through the transparent route server. The opt-in
strict-peer mode closes this:

```toml
[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
route_server_client = true
next_hop_ownership = "strict_peer"
```

With `"strict_peer"` set, an inbound unicast announcement is accepted only
when every address component of its decoded wire next-hop identity is the
advertising session's own address. The check runs **before** import policy,
on the immutable wire value — a policy rewrite can never launder an
unauthorized next hop — and it is fail-closed:

- classic IPv4 `NEXT_HOP`, IPv6 global, and RFC 8950 IPv4-over-IPv6 forms
  must equal the session address exactly;
- address-family differences are literal mismatches: for example, an IPv6
  `MP_REACH_NLRI` next hop on an IPv4 session is always foreign. Use same-AF
  sessions when applying `strict_peer` to both IPv4 and IPv6 unicast;
- a global + link-local next-hop pair is always rejected: the session maps
  to one address, so the companion is unverifiable (never silently ignored);
- a link-local next hop is only accepted from a scoped link-local session
  with that exact address (`fe80::/10` is an identity only together with an
  interface scope);
- an RFC 7999 BLACKHOLE community is not an ownership bypass.

Rejected announcements are dropped treat-as-withdraw style: a rejection that
replaces a previously accepted route withdraws exactly that prior
`(prefix, path_id)` identity; a first-seen rejection emits no withdrawal.
Withdrawals in the same UPDATE are always processed. Each rejection logs at
`warn` with the peer, the rejected prefixes, the offending next-hop tuple,
and a stable `reason` token (`foreign_next_hop`,
`unverified_link_local_companion`, or `unscoped_link_local`).

`next_hop_ownership` requires `route_server_client = true` and inherits from
the peer-group. Unset means no ownership enforcement (RFC 7947 transparency
only). The broader `same_as` / `explicit_authorized` relationships RFC 7948
permits are deferred — see
[ADR-0107](adr/0107-route-server-next-hop-ownership.md). Note that a member
legitimately using a different connection in the same AS as its next hop
will be rejected by the strict pilot; leave the knob unset for such members
until the broader modes ship.

#### Per-client best-path (RFC 7947 §2.3.2 path-hiding mitigation)

A route server applies each member's export policy to the single Loc-RIB
best path: when that best is denied toward a member, the member sees
*nothing* for the prefix even though a policy-permitted alternative exists
(RFC 7947 §2.3 "path hiding"). rustbgpd offers both mitigations the RFC
names:

- **Add-Path to clients** (preferred where the client supports Add-Path
  receive): the server sends multiple paths and the client picks after
  its own filters. This is what `examples/route-server/config.toml` uses.
- **`per_client_best = true`** (the BIRD-`secondary` equivalent) for
  clients without Add-Path: the server walks its candidate paths in
  best-path order and advertises the first one the member's export
  policy permits, at the ordinary single-path wire shape.

```toml
[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
route_server_client = true
per_client_best = true       # this member cannot do Add-Path receive
```

Precedence: if the session negotiates Add-Path send for a family, that
family uses Add-Path and `per_client_best` is ignored for it — the
negotiated capability outranks the fallback (this is not an error).

#### RFC 1997 `NO_EXPORT` egress enforcement (`interpret_rfc1997`)

Routes received carrying `NO_EXPORT` (0xFFFFFF01) or `NO_EXPORT_SUBCONFED`
(0xFFFFFF03) are suppressed at export staging toward eBGP neighbors whose
`interpret_rfc1997` is on. The default is derived: `true` for plain eBGP
and iBGP neighbors, `false` for route-server clients (transparent
pass-through, matching common IXP route-server practice — arouteserver and
IXP Manager deployments expect members, not the server, to enforce the
community). Set the knob explicitly on a neighbor or peer-group to
override either default.

The check applies to the route as received: export policy that *adds*
`NO_EXPORT` still delivers the route (attaching the community for the
receiver to honor is the standard route-server action idiom), and export
policy that *removes* it cannot bypass the suppression. iBGP neighbors
are never suppressed — RFC 1997 permits intra-AS advertisement. The
export-explain ladder reports the suppression on the `no_export` gate
rung.

Notes:

- Requires `route_server_client = true` (and therefore eBGP); validation
  rejects it otherwise. It is mutually exclusive with `orr_vantage` by
  construction (ORR requires an iBGP route-reflector client).
- Per-client-best peers with shareable export chains and unicast-only
  sessions join update groups (ADR-0126): the candidate walk runs once
  per group — the first permitted candidate is the shared winner, and
  the member sourcing it receives the staged runner-up instead — so
  the mitigation costs one extra export evaluation per overlapped
  changed prefix, not O(members). `rbgp neighbor <peer>` reports
  `group:N` for such members; `bgp_update_group_runner_up_entries`
  tracks the staged runner-up lane (grows with announcement overlap,
  never with member count). A peer-context export chain, or a session
  negotiating VPNv4/VPNv6 or RT-Constrain, keeps the peer on the
  per-peer path with the existing `per_client_best` ungrouped reason,
  counted in `bgp_update_group_fallback_peers`.

#### Route-server control communities (RFC 7947 §2.3.2 / RFC 8195, `rs_control_communities`)

A member steers per-target redistribution with communities keyed on the
*target* peer's ASN: `0:PEER` / `RS:0:PEER` (do not announce to `PEER`),
`0:RS` / `RS:0:0` (announce to no one) overridable per target by
`RS:PEER` / `RS:1:PEER`, and `RS:101|102|103:PEER` (prepend the
announcing member's leftmost ASN 1–3× toward `PEER`; `RS:10x:0` = every
target). Standard and RFC 8195 large forms compose.

Enforcement is gated per session by `rs_control_communities` — default
`true` when `route_server_client = true` (the standard IXP posture),
`false` otherwise, inheritable from the peer-group. It is evaluated
pre-policy on the source route, like the RFC 1997 gates, and covers the
unicast export shapes: single-best, Add-Path, and per-client-best
(suppressed candidates are removed before ranking). Acted-on control
communities are scrubbed from the wire-bound announcement toward
enabled sessions; sessions explicitly set off keep RFC 7947 §2.2
byte-level transparency. Enabled sessions stay in shared update-groups:
the filter is route-granular at emit, so only routes actually carrying
a control-form community pay per-target divergence. Suppression shows
up on the `rs_control` export-explain rung.

Full community matrix and evaluation ladder:
[the route-server cookbook](cookbook/route-server.md) and
[RFC_NOTES.md](RFC_NOTES.md#rfc-7947-232--rfc-8195--route-server-control-communities).

To audit the result after neighbor, peer-group, and derived defaults are
resolved, use `rbgp neighbor <address>`. Its Effective Posture block reports
`next_hop_ownership`, `interpret_rfc1997`, `rs_control_communities`, and
`orr_vantage` from the running peer. `rbgp --json neighbor <address>` exposes
the same values under `effective_posture`; an absent object means the daemon is
too old to expose this view, not that the features are disabled. Static and
accepted dynamic peers use the same projection.

### Receive-side Prefix ORF (RFC 5291/5292)

Set `prefix_orf_receive = true` on a neighbor or peer group to advertise that
rustbgpd can receive Address-Prefix ORF entries from that peer. When negotiated,
rustbgpd applies the peer-pushed prefix filter before export policy for that
peer. This is route-server oriented: a client can suppress routes it does not
want to receive without the server pre-configuring a dedicated export policy for
that client.

For an ORF-negotiated family, rustbgpd gates the initial table dump until the
peer sends its first ROUTE-REFRESH for that family, then floods the filtered
view. ORF entries use prefix-list semantics: sequence order, first match wins,
implicit deny on a non-empty list, and permit-all when the list is empty or
removed. `DEFER` installs the filter state but waits for a later immediate or
plain ROUTE-REFRESH to sweep advertisements and withdrawals.

rustbgpd implements the receive side only: it does not send ORF entries to its
own upstreams. The knob is static TOML state, inherited through peer groups, and
is off by default.

### BGP Roles and Only-to-Customer (RFC 9234)

Static eBGP neighbors can advertise a local BGP Role and apply the RFC 9234
Only-to-Customer (OTC) route-leak procedures for IPv4/IPv6 unicast:

```toml
[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
role = "provider"
strict_role = true
```

Valid role values are `"provider"`, `"rs"`, `"rs-client"`, `"customer"`, and
`"peer"`. The longer aliases `"route_server"` and `"route_server_client"` are
also accepted. When `role` is configured, rustbgpd advertises the BGP Role
capability and applies OTC rules based on the local role even if the peer does
not advertise a Role. `strict_role = true` changes that compatibility behavior:
the peer must advertise a compatible Role or the OPEN is rejected with Role
Mismatch (NOTIFICATION 2/11).

OTC handling is scoped to unicast. FlowSpec and EVPN route attributes are not
modified by the v1 implementation. Existing OTC attributes are preserved;
rustbgpd only adds OTC when RFC 9234 requires it and the attribute is absent.
Malformed OTC length is handled as treat-as-withdraw for unicast announcements:
withdrawals in the same UPDATE still apply and the BGP session stays up.
`rbgp neighbor <addr>` and `NeighborService.GetNeighborState` report the
configured local role, any remote role advertised in OPEN, whether the role was
mutually negotiated, and the running `otc_routes_blocked` count.

`role` is eBGP-only and `strict_role` requires `role`. Config reload applies a
role change by reconfiguring the affected peer session; dynamic in-place role
flips without a session restart are deferred in ADR-0071.

### Private AS Removal

Strip private ASNs (64512–65534, 4200000000–4294967294) from AS_PATH
before eBGP advertisement:

```toml
[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
remove_private_as = "all"
```

Three modes are available:

- **`"remove"`** — remove private ASNs only if *every* ASN in the path is private (safe default)
- **`"all"`** — unconditionally remove all private ASNs from every segment; drop empty segments
- **`"replace"`** — replace each private ASN with the local ASN

`remove_private_as` is only valid for eBGP neighbors. Config validation
rejects it on iBGP peers. Route server client peers skip private AS
removal (they already skip AS_PATH manipulation).

See [ADR-0045](adr/0045-private-as-removal.md).

### FlowSpec (RFC 8955)

FlowSpec distributes traffic filtering rules via BGP. Enable it by adding
FlowSpec families to the `families` list:

```toml
[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
families = ["ipv4_unicast", "ipv6_unicast", "ipv4_flowspec", "ipv6_flowspec"]
```

FlowSpec rules have no next-hop (NH length = 0 in MP_REACH_NLRI). Traffic
actions (rate-limit, redirect, DSCP mark) are encoded as extended communities
per RFC 8955 section 7.

FlowSpec routes are injected and queried via the gRPC API:

- `InjectionService/AddFlowSpec` — inject a FlowSpec rule with match components and actions
- `InjectionService/DeleteFlowSpec` — withdraw a FlowSpec rule
- `RibService/ListFlowSpecRoutes` — query the FlowSpec Loc-RIB

FlowSpec routes pass through the same policy engine as unicast routes:
import/export policy, iBGP split-horizon, and route reflector rules all
apply. See [ADR-0035](adr/0035-flowspec.md).

### Per-neighbor policy

Each neighbor can carry its own import and export policy. These are
defined as nested arrays of tables within the `[[neighbors]]` entry.

```toml
[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002

[[neighbors.import_policy]]
prefix = "10.0.0.0/8"
ge = 24
le = 32
action = "deny"

[[neighbors.import_policy]]
prefix = "0.0.0.0/0"
le = 24
action = "permit"
set_local_pref = 200

[[neighbors.export_policy]]
prefix = "192.168.0.0/16"
action = "permit"
set_as_path_prepend = { asn = 65001, count = 2 }
```

See the [Policy entries](#policy-entries) section below for field details.

### Route Reflector (RFC 4456)

rustbgpd can act as a route reflector, relaxing the iBGP full-mesh requirement.
An explicit `cluster_id`, or any valid static or dynamic iBGP client with
`route_reflector_client = true`, enables route-reflector mode. Without an
explicit cluster ID, rustbgpd uses `router_id`. iBGP-learned routes from clients
are reflected to all iBGP peers, while routes from non-clients go to clients only.

```toml
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
cluster_id = "10.0.0.1"    # enables route reflector mode

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65001
route_reflector_client = true    # this peer is a RR client

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65001
# non-client -- receives reflected client routes only
```

See [ADR-0029](adr/0029-route-reflector.md) for reflection rules and
ORIGINATOR_ID/CLUSTER_LIST handling.

### Update groups (automatic)

There is no configuration knob for update groups — rustbgpd groups
outbound peers automatically whenever their staged output is provably
identical: same export-policy chain **content**, same eBGP/iBGP and
RR-client role, same sendable families (unicast, and since v2 the
VPNv4/VPNv6 and RT-Constrain-negotiation dimensions), same advertised
LLGR families. Grouped peers share one staged outbound table, so the
export tail (reflection rules, policy evaluation, equality diff) runs
once per group instead of once per peer — the difference between ~15 s
and sub-second 100k-route convergence at 256 uniform RR clients
(measured; see [ADR-0098](adr/0098-update-groups.md)).

VPNv4/VPNv6 routes are grouped too ([ADR-0099](adr/0099-update-groups-v2.md)),
**including for RT-Constrain-negotiated peers**: RTC no longer implies
the per-peer path for VPN. The RFC 4684 RT filter is applied per
member at emit time, so PE clients with entirely different RT
memberships still share one group and one staging pass, and a
member's RT-membership change emits its minimal wire delta from one
group-table walk with zero policy re-evaluations.

A peer falls back to the plain per-peer path (with identical semantics
— grouping is purely an optimization) when any of these apply:

| Reason | Meaning |
|--------|---------|
| `policy_peer_context` | Its export chain matches on neighbor address/ASN/group, so verdicts can differ per peer |
| `add_path_send` | Add-Path send is negotiated (candidate ranks are per-target) |
| `per_client_best` | RFC 7947 §2.3.2 per-client best-path on a session that also negotiates VPNv4/VPNv6 or RT-Constrain (unicast-only per-client-best sessions with shareable chains group instead, ADR-0126) |
| `orr_vantage` | The peer is bound to an ORR vantage (per-vantage bests, ADR-0095) |
| `orf_installed` | The peer negotiated ORF-receive (peer-pushed outbound filters) |
| `slow_peer` | Slow-peer isolation moved the peer onto its own path; it can rejoin a group after the backlog clears |

RT-Constrain negotiation is deliberately **not** in this table: since
v2 it is part of the group key, not a fallback reason. Add-Path send
remains a fallback for all families (ADR-0099 records why per-member
path-id correction is unsound without per-member state).

`rbgp neighbor <peer>` prints the membership (`group:N`) or the
fallback reason on its `Update Group` line. Metrics:
`bgp_update_groups`, `bgp_update_group_members{group}`,
`bgp_update_group_regroups_total`, `bgp_update_group_fallback_peers`,
`bgp_update_group_interned_chains` and `bgp_update_group_keys`
(registry growth — append-only for the process lifetime),
`bgp_update_group_residue_entries` (withdrawal residue held while a
member is dirty; returns to zero when its resync completes), and
`bgp_update_group_runner_up_entries` (staged per-client-best runner-up
lane entries across groups, ADR-0126 — grows with announcement
overlap, never with member count).

To compare two configured peers without depending on process-local `group:N`
identifiers, query their live memberships directly:

```console
rbgp neighbor 192.0.2.10 --compare 192.0.2.11
rbgp --json neighbor 2001:db8::10 --compare 2001:db8::11
```

The comparison reports one of four verdicts:

| Verdict | Meaning |
|---------|---------|
| `shared` | Both peers are grouped in the same live shared-staging group |
| `separate` | Both peers are grouped, but their staging inputs place them in different groups |
| `private` | Both peers have live outbound membership and at least one uses a per-peer fallback path |
| `unknown` | At least one configured peer has no live outbound registration, or the group metadata is unavailable |

The output names each side's ID-free membership as `grouped`, `unknown`, or one
of the fallback reasons in the table above. For `separate`, `differences` uses
stable semantic categories rather than internal IDs: `export_policy`,
`session_kind`, `route_reflector_client`, `local_role`, `rfc1997_mode`,
`negotiated_families`, and `llgr_families`. `shared`, `private`, and `unknown`
carry no difference list; for private peers, the side-specific membership
reasons explain why shared staging is unavailable.

Ordinary IPv6 literals work as shown above. The normal scoped link-local
neighbor spelling is `fe80::1%eth0`, but live update-group comparison currently
rejects any IPv6 link-local peer (scoped or bare) with `INVALID_ARGUMENT` because
the actor-owned membership registry is keyed by address only. Inspect each
scoped peer's `Update Group` line separately instead.

See [ADR-0098](adr/0098-update-groups.md),
[ADR-0099](adr/0099-update-groups-v2.md), and LAN-456 /
[#1041](https://github.com/lance0/rustbgpd/pull/1041) for the live, ID-free
comparison design.

---

## `[inbound_admission]`

Per-source inbound accept-rate limiting
([ADR-0120](adr/0120-inbound-connection-admission.md)). A token bucket
per aggregated source address bounds how fast a
`[[dynamic_neighbors]]`-matched source can cycle the passive accept
path — a churny or abusive member inside a permitted range is bounded
to `burst` immediate accepts and `rate_per_minute` sustained accepts,
dropped immediately after TCP accept once over rate. Statically
configured neighbor addresses are exempt: a flapping legitimate peer
must never lock itself out of re-establishment. Sources matching no
configuration at all are dropped by the existing unconfigured-source
check before the limiter is consulted.

**Opt-in — default off.** An existing deployment's accept behavior is
unchanged on upgrade. All fields are restart-required; see
[reload-matrix.md](reload-matrix.md#inbound_admission-adr-0120) for the
per-field classification.

```toml
[inbound_admission]
enabled = false          # default; set true to enforce the accept-rate limit
rate_per_minute = 12     # sustained accepts per source aggregate per minute (> 0)
burst = 5                # immediate accepts before the sustained rate applies (> 0)
v4_aggregation_len = 32  # IPv4 bucket-key prefix length (8-32); 32 = per host
v6_aggregation_len = 64  # IPv6 bucket-key prefix length (16-128); per-/128 is trivially evadable
table_capacity = 4096    # tracked source aggregates (64-65536), LRU-evicted at capacity
```

Accounting is per aggregated source: all hosts inside one aggregate
(one v6 /64 by default) share a bucket. The tracking table is a
fixed-capacity LRU, so limiter memory stays bounded (roughly
`table_capacity` × ~100 bytes) regardless of how many sources probe the
listener; an evicted aggregate re-enters with a fresh burst allowance.

Drops are counted in
`bgp_inbound_connections_dropped_total{reason="rate_limited"}`; the
`unconfigured` and `dynamic_limit` reasons account the pre-existing
drop sites and are recorded even while the limiter is disabled. See
`docs/OPERATIONS.md` for the metric reference.

---

## `[rpki]`

Optional. Configures RPKI origin validation via a persistent RTR client (RFC 8210).
rustbgpd connects to one or more RPKI cache validators and uses their VRP
(Validated ROA Payload) data to classify routes as Valid, Invalid, or NotFound.
The RTR session stays connected after `EndOfData`, uses `SerialNotify` for
immediate refreshes when the cache sends them, falls back to periodic serial
polling at `refresh_interval`, and expires cached VRPs if no fresh `EndOfData`
arrives before the effective expiry timer.

### Prerequisites

You need a running RPKI validator that speaks RTR:

| Validator | Default RTR Port | Notes |
|-----------|:----------------:|-------|
| [Routinator](https://nlnetlabs.nl/projects/routinator/) | 3323 | Rust, recommended |
| [rpki-client](https://www.rpki-client.org/) | 8282 | OpenBSD origin |
| [FORT](https://fortproject.net/) | 8323 | C, lightweight |
| [OctoRPKI](https://github.com/cloudflare/cfrpki) | 8282 | Go, Cloudflare |

### Basic setup

```toml
[rpki]
[[rpki.cache_servers]]
address = "127.0.0.1:3323"
```

### Multiple cache servers (redundancy)

For production, connect to 2+ caches. Addresses must be numeric IP endpoints;
DNS hostnames are not supported, and IPv6 addresses must be bracketed. VRPs are
merged (union) across all connected caches:

```toml
[rpki]
[[rpki.cache_servers]]
address = "192.0.2.10:3323"

[[rpki.cache_servers]]
address = "[2001:db8::10]:3323"
```

### Cache server options

| Field | Type | Required | Default | Description |
|-------|------|:--------:|:-------:|-------------|
| `address` | string | yes | -- | Numeric cache server `IP:port`; bracket IPv6 addresses |
| `refresh_interval` | u64 | no | 3600 | Seconds between Serial Queries |
| `retry_interval` | u64 | no | 600 | Seconds before reconnect on failure |
| `expire_interval` | u64 | no | 7200 | Seconds before discarding stale VRPs |

### Validation states

Every route receives a validation state based on RPKI data:

| State | Meaning | Best-path effect |
|-------|---------|------------------|
| **Valid** | Origin AS matches a VRP covering the prefix | Preferred |
| **NotFound** | No VRP covers the prefix | Neutral (default) |
| **Invalid** | VRP covers the prefix but origin AS doesn't match, or the route exceeds the VRP `maxLength` | Deprioritized |

### Policy integration

Use `match_rpki_validation` in import or export policy statements to filter
routes by RPKI state. Import validation evaluates against the current VRP
snapshot at ingress time. Later VRP/ASPA cache updates trigger inbound Route
Refresh for established peers whose resolved import policy matches validation
state, so previously denied routes can be reconsidered against the fresh
snapshot. Peers that are not established evaluate against the fresh snapshot
when they next receive routes.

Drop RPKI-invalid routes (recommended):

```toml
[[policy.definitions.rpki-filter.statements]]
match_rpki_validation = "invalid"
action = "deny"
```

Prefer valid routes with higher LOCAL_PREF:

```toml
[[policy.definitions.rpki-prefer.statements]]
match_rpki_validation = "valid"
action = "permit"
set_local_pref = 200

[[policy.definitions.rpki-prefer.statements]]
match_rpki_validation = "not_found"
action = "permit"
set_local_pref = 100
```

### Monitoring

Prometheus metrics exposed at the configured metrics endpoint:

| Metric | Description |
|--------|-------------|
| `bgp_rpki_vrp_count{af="ipv4\|ipv6"}` | Current VRP entries by address family |

See [ADR-0034](adr/0034-rpki-origin-validation.md) for design details.

---

## `[policy]`

Optional. Defines named policy definitions, global policy chains, and
`.rpol` policy files that apply to all neighbors that do not declare
their own per-neighbor policy.

### Inline policy (removed)

The global inline fallback (`[[policy.import]]` / `[[policy.export]]`)
has been removed: it predated the current policy architecture, was
restart-required on change (no SIGHUP hot-apply), and was invisible to
config transactions and the impact planner. A config that still sets it
fails to load with an ordinary unknown-field diagnostic. Move the statements to
[named policy definitions](#named-policy-definitions) referenced from
`import_chain` / `export_chain`, or to
[`.rpol` policy files](rpol-language.md) via `policy.rpol_files`.
Per-neighbor inline policy (`[[neighbors.import_policy]]` /
`[[neighbors.export_policy]]`) is **unchanged**.

### Named policy definitions

Named policies are reusable policy blocks defined under `[policy.definitions]`.
Each has a name, optional `default_action` (default: `"permit"`), and a list of
statements. The same named definitions and chain attachments can also be
managed at runtime through the gRPC `PolicyService`; successful mutations are
persisted back to TOML.

```toml
[policy.definitions.reject-bogons]
default_action = "deny"
[[policy.definitions.reject-bogons.statements]]
action = "permit"
prefix = "0.0.0.0/0"
ge = 8
le = 24

[policy.definitions.set-lp-customer]
[[policy.definitions.set-lp-customer.statements]]
action = "permit"
set_local_pref = 150

[policy.definitions.tag-ixp]
[[policy.definitions.tag-ixp.statements]]
action = "permit"
set_community_add = ["LC:65001:1:100"]
set_next_hop = "self"
```

| Field            | Type   | Required | Default    | Description                             |
|------------------|--------|----------|------------|-----------------------------------------|
| `default_action` | string | no       | `"permit"` | Action when no statement matches (`"permit"` or `"deny"`) |
| `statements`     | array  | no       | `[]`       | Policy statements (same schema as inline entries) |

### Neighbor sets

Neighbor sets are reusable peer identity groups for policy matching. They live
under `[policy.neighbor_sets.<name>]` and can match by exact neighbor address,
remote ASN, and/or peer-group name. A policy statement references one with
`match_neighbor_set = "..."`. Neighbor sets are also manageable at runtime via
the gRPC `PolicyService`.

```toml
[policy.neighbor_sets.ixp-clients]
addresses = ["10.0.0.2", "10.0.0.3"]
remote_asns = [65002, 65003]
peer_groups = ["rs-clients"]
```

### Policy chains

Policy chains reference named definitions by name, evaluated in order with
GoBGP-style semantics:

- **Permit** — accumulate route modifications, continue to next policy
- **Deny** — reject immediately, stop the chain
- **After all policies** — implicit permit with all accumulated modifications

Global chains:

```toml
[policy]
import_chain = ["reject-bogons", "set-lp-customer"]
export_chain = ["tag-ixp"]
```

Per-neighbor chains (override global):

```toml
[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
import_policy_chain = ["reject-bogons", "set-lp-customer"]
export_policy_chain = ["tag-ixp"]
```

When multiple policies in a chain both set a scalar value (e.g. `set_local_pref`),
the later policy wins. List values (community add/remove) accumulate across the
chain.

**Mutual exclusion:** Inline policy and policy chain cannot both be set for the
same direction on the same neighbor. This is a config validation error.

### `.rpol` policy files (`rpol_files`, ADR-0096)

Policies written in the rustbgpd policy language
([`rpol-language.md`](rpol-language.md)) load from files referenced in
`[policy]`:

```toml
[policy]
rpol_files = ["policies/core.rpol", "policies/customers.rpol"]
```

- **Paths** are relative to the config file's directory (absolute paths
  work too). After a successful load the daemon carries them as
  absolute paths, so runtime config snapshots and transaction
  candidates stay loadable regardless of working directory.
- **Compile-at-load:** every file is parsed and typechecked at config
  load; any diagnostic (rendered with source excerpts, like
  `rbgp policy check`) is a config load error — a broken `.rpol` file
  never half-loads.
- **Import roots (`rpol_roots`):** an optional array of extra
  directories for `.rpol` `import` resolution. An import resolves
  against the importing file's directory first, then against these
  roots in order; the resolved file must stay inside the main file's
  directory or one of the roots. Relative entries resolve against the
  config file's directory and are rewritten absolute at load, like
  `rpol_files`. See [`rpol-language.md`](rpol-language.md) for module
  resolution details.
- **Graph budget (`rpol_max_graph_bytes`):** total source-byte budget
  for each compilation unit's resolved module graph (the `rpol_files`
  entry plus everything its `import` graph pulls in), range
  1 MiB–4 GiB. Default 256 MiB: large enough that IRR-scale
  route-server policies (a 320-member exchange with 1k–40k-entry IRR
  prefix lists renders to ~65 MB) load with headroom, while still
  stopping unbounded or recursively generated graphs at load time. A
  unit over the budget is a config load error naming the file.
- **One namespace:** `.rpol` policies and `[policy.definitions]` TOML
  policies share the named-policy namespace. A name defined by both —
  or by two `.rpol` files — is a load error naming both sources.
- **Chain references:** chains mix TOML and `.rpol` policies freely.
  Parameterized `.rpol` policies are referenced in call-form with
  `u32` arguments, monomorphized at load:

```toml
[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
import_policy_chain = ["customer-in(200)", "bogon-filter", "toml-defined"]
```

  Unknown names, wrong arity, and non-`u32` arguments are load errors.
- **Reload:** editing a referenced `.rpol` file and sending SIGHUP
  recompiles it and hot-applies the changed chains to exactly the
  peers whose resolved policy actually changed (Route Refresh fires
  for materially changed import chains — same mechanism as
  `[policy.definitions]` edits). `rbgp config diff` reports the change
  under the policy section.
- **Scope notes:** config transactions fail closed while either the running or
  candidate config references external `.rpol` graphs or policy datasets if
  the selected executor would adopt the full candidate snapshot. The files
  live outside the candidate TOML, transaction token, and rollback payload.
  This applies to native apply/rollback and gNMI Set. Deploy TOML, `.rpol`
  graphs, and datasets together, then use SIGHUP. True no-ops and pure
  `[[fib_tables]]` transactions with unchanged external inputs remain
  available because the FIB executor substitutes only its targeted table set.
  `rbgp policy explain` statement
  traces cover `.rpol` chain members at term granularity, and
  `rbgp policy stats` reads the installed chains' live per-term hit
  counters (see [`rpol-language.md`](rpol-language.md)).

Test `.rpol` policies without touching the daemon
(`rbgp policy check file.rpol` — runs the file's in-language `test`
blocks locally) or against the daemon's live RIB read-only
(`rbgp policy test` — see [`rpol-language.md`](rpol-language.md)).

### External policy datasets (`[policy.datasets]`, LAN-305)

Each `dataset` declared in a loaded `.rpol` file binds to a snapshot
file here:

```toml
[policy.datasets.customers]
path = "/var/lib/rustbgpd/datasets/customers.list"
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `path` | string | (required) | Snapshot file for the declared dataset: one entry per line, `#` comments, entries in the declared kind's set-literal syntax. Relative paths resolve against the config file's directory and are rewritten absolute at load. |

- The dataset's **kind** lives in the `.rpol` declaration
  (`dataset asn-set customers`), not here — the config only maps
  names to files. Every declared dataset needs an entry and every
  entry needs a declaration; both directions are load errors.
- Files are read at config load and re-read on every SIGHUP reload
  (the refresh trigger — there is no file watcher or dedicated RPC).
  Changed content swaps atomically (generation bump) and refreshes
  only the peers whose chains reference the dataset; unchanged
  content is a no-op; a file that fails to load or parse **keeps the
  prior snapshot** with a WARN, a
  `bgp_policy_dataset_refresh_errors_total{dataset}` counter
  increment, and a `last refresh FAILED` row in `rbgp policy stats`.
  At initial load (or for a newly declared dataset) the file must
  load cleanly.
- Bounds: 64 MiB and 1,000,000 records per file; at most 16 datasets
  per `.rpol` compilation unit.
- Producers should write-temp-then-rename so a refresh never reads a
  torn file. Full format, semantics, and the operator how-to:
  [`rpol-language.md`](rpol-language.md) § Datasets.

### Import-decision explain (`[policy.explain]`)

**Opt-in.** Controls the per-session import-decision cache that backs
`PolicyService.ExplainImportPolicy` and `rbgp policy explain`
(ADR-0073). Every import evaluation — permit **and** deny — is recorded
at the transport eval site keyed by `(AFI, SAFI, prefix, path_id)`, so a
prefix that was denied and never reached the RIB stays explainable.

Omitting the section leaves import explain **disabled**: the inbound
path stores nothing, no cache is allocated, and explain queries answer
`cache_disabled`.

```toml
[policy.explain]
enabled = true
cache_size = 4096
```

| Field        | Type    | Required | Default | Description |
|--------------|---------|----------|---------|-------------|
| `enabled`    | bool    | no       | `false` | Gates the cache write-path. When `false` (the default), the inbound UPDATE path skips the compact decision/context snapshot entirely (one boolean check, nothing stored), the session allocates no cache, and explain queries answer `cache_disabled` (distinct from `not_seen`; the CLI renders it as an error naming the config lines to add). |
| `cache_size` | integer | no       | `4096`  | LRU capacity **per session**, one entry per `(AFI, SAFI, prefix, path_id)`. The 4096 default suits fabric / partial-table peers; a full-table peer keeps it saturated, so raise it toward that peer's retained-prefix count if you need reliable full-table explain. |

**Both settings are global.** There is no per-peer or per-group
override: `enabled` is on or off for the whole daemon, and `cache_size`
is one number applied to every session. "Enable it, but not on the hot
full-table peers" is not a posture this knob offers — it is the whole
daemon, or nothing.

**Sizing the choice.** Retention at the default size is
**partial-table**, not complete. Budget roughly:

```
peers × (154 KiB + min(cache_size, distinct prefixes per peer) × 587 B)
```

The fixed and per-entry terms are a **computed model** solved from two
same-binary fleet shapes in the
[`explain-cache opt-in receipt`](perf/explain-cache-opt-in-2026-07.md).
Worked examples: 10 saturated peers ≈ 24.4 MiB; 1000 peers × 400
retained prefixes ≈ 374 MiB; 1000 peers each announcing at least 4096
distinct routes ≈ 2.4 GiB, the extrapolated saturation ceiling for that
fleet shape. The receipt computes the 1000 × 400 steady-RSS difference
from four measured runs and discloses the fleet, allocator, and host limits.

This is **diagnostic state only** — it never affects which routes are
accepted. Scope is IPv4 / IPv6 unicast. The cache resets on peer session
reset and is **not durable across restart** (for durable history use the
event-history outbox, ADR-0072). Both fields are **restart-required
per-peer** on reload — a session already established keeps its current
behaviour until it re-establishes; see
[`reload-matrix.md`](reload-matrix.md) and the "Explain an import
decision" runbook in [`OPERATIONS.md`](OPERATIONS.md).

### Rejected-route retention (`[policy.reject_retention]`)

Optional. Controls the per-session rejected-route retention store that
backs `rbgp rib received <peer> --rejected` and
`PolicyService.ListRejectedRoutes` — the looking-glass filtered-route
surface. Every rejected inbound unicast announcement — policy deny
(including RPKI/ASPA-driven denies), RFC 9234 OTC route-leak drop,
strict-peer next-hop ownership, AS_PATH/reflection loop, and RFC 7606
treat-as-withdraw — is retained with its canonical reason token, so a
member's "why isn't my route accepted?" is answerable without knowing
the prefix in advance. An identity that is later accepted or explicitly
withdrawn drops out of the store.

```toml
[policy.reject_retention]
enabled = true
capacity = 1024
```

| Field      | Type    | Required | Default | Description |
|------------|---------|----------|---------|-------------|
| `enabled`  | bool    | no       | `true`  | Gates retention entirely. When `false`, the reject paths skip entry construction (one boolean check per gate) and the query surface reports the disabled state as a configuration fact rather than an empty answer. |
| `capacity` | integer | no       | `1024`  | Per-peer retention cap, LRU on rejection recency — a reject storm converges on the most recent `capacity` rejections. Each entry is one rejected `(AFI, SAFI, prefix, path_id)` with its reason and a compact attribute summary, ≤ ~512 bytes realistic worst case ⇒ ~0.5 MiB bound per peer at the default. Raise it toward the expected member announcement count for full coverage on route-server fleets. |

With retention enabled, a clean permitted UPDATE does not construct a
rejection summary. The first policy, OTC, or next-hop-ownership rejection in
an UPDATE builds one bounded prototype shared by that UPDATE's identities.

Like `[policy.explain]`, this is **diagnostic state only** — it never
affects which routes are accepted. Scope is IPv4 / IPv6 unicast
(max-prefix violations tear the session down, so there is no per-route
rejection to retain). The store resets on peer session reset. Both
fields are **restart-required per-peer** on reload; see
[`reload-matrix.md`](reload-matrix.md) and the "Answer a member's 'why
is my route filtered?'" runbook in [`OPERATIONS.md`](OPERATIONS.md).

---

## Policy entries

Named-definition statements (`[[policy.definitions.<name>.statements]]`)
and per-neighbor inline entries (`[[neighbors.import_policy]]` /
`[[neighbors.export_policy]]`) share the same schema.

### Match conditions

Each entry must have at least one match condition. Multiple conditions on the
same entry are ANDed.

| Field                    | Type     | Required | Description                                           |
|--------------------------|----------|----------|-------------------------------------------------------|
| `prefix`                 | string   | no*      | Network prefix in CIDR notation (IPv4 or IPv6)        |
| `ge`                     | u8       | no       | Minimum prefix length to match (inclusive)            |
| `le`                     | u8       | no       | Maximum prefix length to match (inclusive)            |
| `match_community`        | [string] | no*      | Community match criteria (see below). OR within list. |
| `match_as_path`          | string   | no*      | AS_PATH regex (Cisco/Quagga style, `_` = boundary)    |
| `match_neighbor_set`     | string   | no*      | Named neighbor set matched against the evaluation peer |
| `match_route_type`       | string   | no*      | Route source type: `"local"`, `"internal"`, `"external"` |
| `match_as_path_length_ge`| u32      | no*      | Minimum AS_PATH length to match (inclusive)           |
| `match_as_path_length_le`| u32      | no*      | Maximum AS_PATH length to match (inclusive)           |
| `match_local_pref_ge`    | u32      | no*      | Minimum `LOCAL_PREF` to match (inclusive)             |
| `match_local_pref_le`    | u32      | no*      | Maximum `LOCAL_PREF` to match (inclusive)             |
| `match_med_ge`           | u32      | no*      | Minimum MED to match (inclusive)                      |
| `match_med_le`           | u32      | no*      | Maximum MED to match (inclusive)                      |
| `match_next_hop`         | string   | no*      | Exact next-hop IP address to match (unicast only)     |
| `match_rpki_validation`  | string   | no*      | RPKI state: `"valid"`, `"invalid"`, or `"not_found"` |
| `match_aspa_validation`  | string   | no*      | ASPA state: `"valid"`, `"invalid"`, or `"unknown"` |
| `action`                 | string   | yes      | `"permit"` or `"deny"`                                |

*At least one of `prefix`, `match_community`, `match_as_path`,
`match_neighbor_set`, `match_route_type`, `match_as_path_length_ge`,
`match_as_path_length_le`, `match_local_pref_ge`, `match_local_pref_le`,
`match_med_ge`, `match_med_le`, `match_next_hop`, or
`match_rpki_validation` / `match_aspa_validation` is required.

ASPA verification is an IPv4/IPv6-unicast edge-ingress signal. eBGP routes
are verified even when no BGP Role is configured; a Role selects verification
direction. Transparent sessions retain the first-AS exception when configured
with either `route_server_client = true` or the local `rs-client` Role. RFC 6793
OLD peers are checked after AS_PATH reconstruction. Routes learned over iBGP
always present `aspa = "unknown"` to import policy and keep that state across
ASPA cache revalidation, following
`draft-ietf-sidrops-aspa-verification-27` §6.2's recommendation against
internal-session verification.

### Route modifications (set actions)

These fields modify matching routes. Only valid with `action = "permit"`.

| Field                  | Type        | Description                                        |
|------------------------|-------------|----------------------------------------------------|
| `set_local_pref`       | u32         | Set LOCAL_PREF on matching routes                  |
| `set_med`              | u32         | Set MED on matching routes                         |
| `set_next_hop`         | string      | `"self"` or an IP address                          |
| `set_community_add`    | [string]    | Communities to add (standard, EC, or LC format)    |
| `set_community_remove` | [string]    | Communities to remove                              |
| `set_as_path_prepend`  | table       | `{ asn = 65001, count = 3 }` (count 1-10)         |

### Community formats

The `match_community`, `set_community_add`, and `set_community_remove` fields
accept these formats:

| Format | Example | Type |
|--------|---------|------|
| `ASN:VALUE` | `"65001:100"` | Standard community |
| Well-known name | `"NO_EXPORT"`, `"NO_ADVERTISE"`, `"NO_EXPORT_SUBCONFED"`, `"BLACKHOLE"`, `"GRACEFUL_SHUTDOWN"` | Standard community |
| `RT:ADMIN:VALUE` | `"RT:65001:100"`, `"RT:192.0.2.1:100"` | Extended community (route target) |
| `RO:ADMIN:VALUE` | `"RO:65001:200"`, `"RO:192.0.2.1:200"` | Extended community (route origin) |
| Well-known name | `"OV_VALID"`, `"OV_NOT_FOUND"`, `"OV_INVALID"` | Extended community (RFC 8097 origin-validation state; matched/added/removed by exact wire value) |
| `LC:G:L1:L2` | `"LC:65001:100:200"` | Large community (RFC 8092) |

RT/RO actions select the administrator-specific wire format from the literal:
numeric ASNs through 65535 use the RFC 4360 two-octet-AS form (type `0x00`)
with a 32-bit local administrator, larger ASNs use the RFC 5668 four-octet-AS
form (type `0x02`) with a 16-bit local administrator, and dotted IPv4
administrators use the RFC 4360 IPv4-specific form (type `0x01`) with a 16-bit
local administrator. Thus `RT:65535:70000` is valid, while
`RT:65536:70000` and `RT:192.0.2.1:70000` are rejected. Match expressions
remain encoding-agnostic across the three forms.

### AS_PATH regex

The `match_as_path` field accepts regular expressions with the Cisco/Quagga `_`
boundary convention. `_` expands to `(?:^| |$|[{}])` before compilation, matching
the start of the string, a space between ASNs, the end of the string, or
`AS_SET` delimiters (`{`/`}`).

| Pattern | Matches |
|---------|---------|
| `^65100_` | AS_PATH starting with 65100 |
| `_65200$` | AS_PATH ending with 65200 |
| `_65300_` | AS_PATH containing 65300 |
| `^65100$` | AS_PATH that is exactly 65100 |

Entries are evaluated in order. The first matching entry wins. If no entry
matches, the default action is **permit**.

### AS_PATH length matching

Use `match_as_path_length_ge` / `match_as_path_length_le` to match routes by
inclusive AS_PATH length. Either field may be used independently or together
as a range. `AS_SET` counts as 1 per RFC 4271.

```toml
[[policy.definitions.path-length-guard.statements]]
match_as_path_length_ge = 3
match_as_path_length_le = 8
action = "deny"
```

### Neighbor-set, route-type, next-hop, and MED / `LOCAL_PREF` matching

`match_neighbor_set` evaluates against the peer currently being evaluated by
policy:

- import policy: the source peer that sent the route
- export policy: the destination peer receiving the route

`match_route_type` distinguishes:

- `"external"` — learned from an eBGP peer
- `"internal"` — learned from an iBGP peer
- `"local"` — locally injected or originated

`match_local_pref_*` and `match_med_*` are inclusive comparisons. When the
route does not carry the attribute on the wire (typical for `LOCAL_PREF` on
eBGP-received routes), the engine substitutes the RFC 4271 implicit defaults
— 100 for `LOCAL_PREF` (§5.1.5), 0 for `MED` (§5.1.4) — and matches against
those. A single policy `match_local_pref_ge = 100` therefore reads
identically against iBGP routes (LP attribute on the wire) and eBGP routes
(no LP on the wire). Matches FRR / BIRD / GoBGP convention. To match only
routes with an explicit attribute, pair the numeric match with
`match_route_type = "internal"` (LP) or a more specific filter.

`match_next_hop` is exact IP equality against the route's resolved next hop.
It applies to unicast routes. FlowSpec routes do not expose a policy-matchable
next hop because FlowSpec `MP_REACH_NLRI` carries NH length 0.

```toml
[[policy.definitions.ixp-export.statements]]
match_neighbor_set = "ixp-clients"
match_route_type = "external"
match_next_hop = "2001:db8::1"
match_local_pref_ge = 200
match_med_le = 50
action = "permit"
set_community_add = ["65001:100"]
```

### Prefix length matching

Without `ge`/`le`, only exact prefix-length matches count. With them, a route
matches if its prefix falls within the given network *and* its mask length is
within `[ge, le]`.

Example -- deny all specifics of 10.0.0.0/8 longer than /24:

```toml
[[policy.definitions.deny-specifics.statements]]
prefix = "10.0.0.0/8"
ge = 25
le = 32
action = "deny"
```

---

## Policy resolution order

For each neighbor, import and export policies are resolved independently:

1. If the neighbor has a per-neighbor **policy chain** (`import_policy_chain` /
   `export_policy_chain`), that chain is used.
2. If the neighbor has per-neighbor **inline policy** (`[[neighbors.import_policy]]`
   or `[[neighbors.export_policy]]`), those are wrapped in a single-element chain.
3. Otherwise, the global **chain** (`import_chain` / `export_chain`) is used.
4. If none of the above exist, all routes are permitted (no filtering).

Per-neighbor policy completely replaces the global policy for that direction --
the two are never merged. Inline and chain on the same neighbor/direction is a
config error.

---

## Complete example

A realistic configuration with three peers, policy actions, and community matching:

```toml
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

# gRPC defaults to a UDS at <runtime_state_dir>/grpc.sock when no listener
# is configured. Uncomment below to add a TCP listener (UDS stays active
# unless explicitly disabled with [global.telemetry.grpc_uds] enabled = false).
# [global.telemetry.grpc_tcp]
# address = "127.0.0.1:50051"
# token_file = "/etc/rustbgpd/grpc.token"

# Global import policy: deny default route and RFC 1918, permit up to /24
[policy]
import_chain = ["edge-import"]

[policy.definitions.edge-import]
[[policy.definitions.edge-import.statements]]
prefix = "0.0.0.0/0"
action = "deny"

[[policy.definitions.edge-import.statements]]
prefix = "10.0.0.0/8"
le = 32
action = "deny"

[[policy.definitions.edge-import.statements]]
prefix = "172.16.0.0/12"
le = 32
action = "deny"

[[policy.definitions.edge-import.statements]]
prefix = "192.168.0.0/16"
le = 32
action = "deny"

# Prefer routes from AS 65100
[[policy.definitions.edge-import.statements]]
match_as_path = "^65100_"
action = "permit"
set_local_pref = 200

[[policy.definitions.edge-import.statements]]
prefix = "0.0.0.0/0"
le = 24
action = "permit"

# Upstream provider -- uses global import policy, custom export with prepend
[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
description = "upstream-provider"
hold_time = 90
max_prefixes = 50000

[[neighbors.export_policy]]
prefix = "192.168.1.0/24"
action = "permit"
set_as_path_prepend = { asn = 65001, count = 2 }

[[neighbors.export_policy]]
prefix = "192.168.2.0/24"
action = "permit"

[[neighbors.export_policy]]
prefix = "0.0.0.0/0"
le = 32
action = "deny"

# IXP route server -- tag routes with large community, next-hop self
[[neighbors]]
address = "10.0.1.2"
remote_asn = 65100
description = "ixp-rs1"
hold_time = 90

[[neighbors.export_policy]]
action = "permit"
prefix = "0.0.0.0/0"
le = 24
set_next_hop = "self"
set_community_add = ["LC:65001:1:100"]

# eBGP peer with MD5 auth -- per-peer import to reject specifics
[[neighbors]]
address = "10.0.2.2"
remote_asn = 65200
description = "peer-secure"
hold_time = 180
md5_password = "s3cret"
ttl_security = true
max_prefixes = 10000

[[neighbors.import_policy]]
prefix = "10.0.0.0/8"
ge = 25
le = 32
action = "deny"

[[neighbors.import_policy]]
prefix = "0.0.0.0/0"
le = 24
action = "permit"
set_med = 50
```

---

## `[bmp]`

Optional. Configures BMP (BGP Monitoring Protocol, RFC 7854 + RFC 8671 +
RFC 9069) export to external collectors. rustbgpd acts as a BMP client, initiating TCP
connections to each configured collector and streaming BGP state changes (peer
up/down, route monitoring) as BMP messages.

```toml
[bmp]
sys_name = "rustbgpd"          # optional, default "rustbgpd"
sys_descr = "my bgp speaker"   # optional, default "rustbgpd <version>"

[[bmp.collectors]]
address = "10.0.0.100:11019"
reconnect_interval = 30        # seconds, default 30
# monitor defaults to ["rib_in_pre"] (RFC 7854 behavior)

[[bmp.collectors]]
address = "10.0.0.101:11019"
monitor = ["rib_in_pre", "rib_out_post"]   # + RFC 8671 Adj-RIB-Out
```

### BMP section fields

| Field       | Type   | Required | Default      | Description                          |
|-------------|--------|----------|--------------|--------------------------------------|
| `sys_name`  | string | no       | `"rustbgpd"` | System name in BMP Initiation message |
| `sys_descr` | string | no       | version string | System description in BMP Initiation message |
| `collectors`| array  | no       | `[]`         | List of BMP collector endpoints       |

### Collector fields

| Field                | Type   | Required | Default | Description                          |
|----------------------|--------|----------|---------|--------------------------------------|
| `address`            | string | yes      | --      | Collector `host:port` socket address  |
| `reconnect_interval` | u64   | no       | 30      | Seconds between reconnect attempts    |
| `monitor`            | array  | no       | `["rib_in_pre"]` | Route-monitoring streams: `rib_in_pre` (RFC 7854 pre-policy Adj-RIB-In), `rib_out_post` (RFC 8671 post-policy Adj-RIB-Out), and/or `loc_rib` (RFC 9069 Loc-RIB instance with collector-connect table sync) |
| `version`            | u8     | no       | 3       | BMP wire version framed for this collector: `3` (RFC 7854) or `4` (BMPv4 TLV framing, see below) |

### BMPv4 framing (`version = 4`)

With `version = 4` on a collector, every BMP message carries common-header
version 4 per draft-ietf-grow-bmp-tlv-20: Route Monitoring messages enclose
the BGP UPDATE PDU in the mandatory BGP Message TLV (type 7, index 0) and
Stats Reports enclose the Stats Count + stats data in the mandatory Stats
TLV (code point 1). Peer Up/Down, Initiation, and Termination already
provision TLV data in v3 and differ only in the version byte. Framing is
per collector — v3 and v4 collectors can be mixed freely, and v3 output is
byte-identical to previous releases.

**Path marking (automatic, no knob):** on `loc_rib` Route Monitoring
messages a v4 collector also receives the Path Marking TLV
(draft-ietf-grow-bmp-path-marking-tlv-05): a Path Status bitmap marking
every announced Loc-RIB route `Best` (plus `Stale` when the GR/LLGR
machinery holds it stale) and, when a competing path was compared, the
optional Reason Code naming the decisive best-path step (local
preference, AS path length, origin, MED, peer type, router ID, peer
address). Bits a route reflector cannot attest to (Primary/Backup/
Non-installed/Filtered/Suppressed — FIB, policy-drop, and damping
concepts) are never set. `rib_in_pre` and `rib_out_post` streams carry
no marking: the rib-in tap fires before best-path selection and rib-out
is per-peer staged output, so neither has an honest decision status.
Withdrawals carry no marking. v3 collectors are unaffected.

**Pre-IANA caveat:** BMPv4 is an IETF draft. The TLV code points are not
yet IANA-assigned and may be renumbered when the draft is published as an
RFC; pick `4` only for collectors that track the same draft revision
(e.g. bleeding-edge pmacct/gobmp builds). The default `3` is the stable
RFC 7854 encoding. In particular the Path Marking TLV self-assigns type
5, which collides with tlv-20's VRF/Table Name TLV (also type 5) —
rustbgpd never emits the latter, so its own v4 output is unambiguous,
but expect a renumber at RFC publication.

### What is streamed

BMP messages sent to collectors:

| Message | When |
|---------|------|
| **Initiation** (Type 4) | On TCP connect to collector |
| **Peer Up** (Type 3) | BGP session reaches Established (includes raw OPEN PDUs) |
| **Peer Down** (Type 2) | BGP session leaves Established |
| **Route Monitoring** (Type 0) | Inbound UPDATE received (pre-policy, raw PDU); with `rib_out_post`, also every outbound UPDATE (post-policy Adj-RIB-Out, RFC 8671); with `loc_rib`, every Loc-RIB best-path change plus the connect-time table dump (RFC 9069) |
| **Stats Report** (Type 1) | Periodic per-peer export every 60s (Adj-RIB-In count type 7; post-policy Adj-RIB-Out gauges type 15 + per-AFI/SAFI type 17; with `loc_rib`, Loc-RIB gauges type 8 + per-AFI/SAFI type 10) |
| **Termination** (Type 5) | On coordinated daemon shutdown (and on client channel shutdown) |

Route Monitoring messages carry the original raw BGP UPDATE PDU bytes
(including the 19-byte BGP header), enabling collectors to decode the full
UPDATE without loss.

### RFC 8671 Adj-RIB-Out monitoring

With `monitor = ["rib_out_post"]` (combinable with `rib_in_pre`), every
outbound UPDATE — announcements, withdraws, and End-of-RIB markers, across all
address families — is mirrored to the collector byte-exact as transmitted,
with the per-peer header O flag set (Adj-RIB-Out) and L flag set
(post-policy). The peer address/AS/BGP-ID identify the remote peer receiving
the routes; the timestamp is the advertise time. Pre-policy Adj-RIB-Out
(O=1, L=0) is deliberately not implemented.

Note: the rib-out stream is live-only. A collector that connects (or
reconnects) mid-session receives Peer Up state replay but no synthesized
table dump of already-advertised routes — the same limitation the rib-in
stream has today. The `loc_rib` view below does not share this gap. See
[KNOWN_ISSUES.md](../KNOWN_ISSUES.md).

### RFC 9069 Loc-RIB monitoring

With `monitor = ["loc_rib"]` (combinable with the other views), the daemon
streams its post-best-path Loc-RIB attributed to an emulated *Loc-RIB
instance peer* (peer type 3): zero-filled peer address, Peer Distinguisher 0
(global instance), Peer AS = the local ASN, Peer BGP ID = the local
router-id, and a per-message timestamp equal to the route's Loc-RIB install
time. Route Monitoring PDUs are synthesized from the RIB with 4-octet-ASN
encoding and no Add-Path. The Peer Up for the emulated peer carries a
fabricated OPEN (4-octet-ASN capability plus one MP capability per streamed
family; the received OPEN is a byte-identical repeat) and the VRF/Table Name
Information TLV with the value `global`; on daemon shutdown the peer goes
down with reason 6 and the TLV echoed. Periodic stats include type 8
(Loc-RIB route total) and type 10 (per-AFI/SAFI counts).

Streamed families (v1): IPv4/IPv6 unicast and VPNv4/VPNv6. Other Loc-RIB
families (EVPN, BGP-LS, labeled-unicast, FlowSpec, RT-Constrain) are not yet
synthesized and are deliberately absent from the fabricated OPEN; they land
additively in a later slice.

**Collector-connect table sync.** Unlike the rib-in/rib-out views, every
collector (re)connect on a `loc_rib` collector triggers a full Loc-RIB dump:
Peer Up for the emulated peer, then the current table as Route Monitoring
messages (each stamped with its install time), closed by one End-of-RIB per
streamed family, after which live updates continue seamlessly. Live changes
racing the dump may be observed both in the dump and as live messages — the
standard BMP overlap; collectors reconcile by prefix. The dump is paced to
the collector's TCP drain rate. Every TCP attempt gets a fresh queue; the client
writes cached ordinary and Loc-RIB Peer Ups before confirming the generation,
and only then does the manager start the dump. Request admission, RIB replies,
and collector delivery are independently bounded. A failure before the
RIB-owned terminal End-of-RIB closure increments
`bmp_collector_drops_total{phase="loc_rib_dump"}`, discards buffered live
Loc-RIB rows, and suppresses that view until the next reconnect rather than
releasing an incomplete snapshot. More than 8,192 live rows buffered behind
bootstrap or an in-flight dump closes only that collector's TCP generation;
the reconnect starts a fresh cursor-less dump, so an End-of-RIB cannot certify
a view with a dropped live delta.

All Loc-RIB messages — including the emulated peer's Peer Up/Down and stats
— go only to collectors that monitor `loc_rib`.

When BMP is not configured, overhead remains minimal: raw frame capture uses
`Bytes` refcount clones (no message-data copy). Loc-RIB PDU synthesis runs
only when at least one collector monitors `loc_rib`.

---

## `[gnmi_dialout]`

Optional. Configures gNMI dial-out streaming telemetry: the daemon opens a
persistent gRPC connection OUT to each configured collector and pushes the
same OpenConfig telemetry a dial-in `gnmi.gNMI/Subscribe` STREAM
subscription would produce — an initial snapshot, a `sync_response`
marker, then updates (periodic samples or ON_CHANGE events). This is the
device-behind-NAT / central-sink ingestion model large fleets use instead
of per-device dial-in. The wire contract is
`rustbgpd.gnmi_dialout.v1.GnmiDialout/Publish` (a device-initiated
`stream gnmi.SubscribeResponse`; see `proto/rustbgpd_dialout.proto`).

```toml
[gnmi_dialout]

[[gnmi_dialout.targets]]
name = "collector-a"                    # unique; metric label + log key
address = "telemetry.example.net:57400" # host:port, DNS allowed
paths = [
  "network-instances/network-instance[name=DEFAULT]/protocols/protocol[identifier=BGP][name=BGP]/bgp/neighbors/neighbor[neighbor-address=*]/state/session-state",
]
mode = "on_change"                      # or "sample" (default)
# sample_interval = 10                  # seconds, SAMPLE mode only
# backoff_initial = 1                   # seconds, first retry delay
# backoff_max = 30                      # seconds, retry delay cap
tls_ca_file = "/etc/rustbgpd/collector-ca.pem"
tls_cert_file = "/etc/rustbgpd/client.pem"   # optional (mutual TLS)
tls_key_file = "/etc/rustbgpd/client.key"    # required with tls_cert_file
# tls_server_name = "collector.example"      # when dialing by IP
```

### Target fields

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `name` | string | yes | -- | Unique target name; the `gnmi_dialout_connected{target}` metric label and log key |
| `address` | string | yes | -- | Collector `host:port` (DNS names allowed; bracket IPv6 literals) |
| `paths` | array | yes | -- | OpenConfig gNMI paths in xpath form — the same path surface the dial-in Subscribe server supports (see `docs/GNMI.md`) |
| `mode` | string | no | `"sample"` | `"sample"` (periodic resample) or `"on_change"` (event-driven; v1 covers the `session-state` leaf and requires `[event_history].enabled = true`) |
| `sample_interval` | u64 | no | 10 | Seconds between samples in SAMPLE mode; values from 1 through 3600 are retained, while zero and values above 3600 are rejected |
| `backoff_initial` | u64 | no | 1 | First reconnect delay in seconds; doubles per consecutive failure |
| `backoff_max` | u64 | no | 30 | Reconnect delay cap in seconds |
| `tls_ca_file` | string | no | -- | CA bundle (PEM path) verifying the collector's server certificate; setting it enables TLS |
| `tls_cert_file` | string | no | -- | Client certificate (PEM path) for mutual TLS; requires `tls_key_file` + `tls_ca_file` |
| `tls_key_file` | string | no | -- | Client private key (PEM path); required together with `tls_cert_file` |
| `tls_server_name` | string | no | dialed host | Expected TLS server name when dialing by IP |

**TLS rules.** `tls_cert_file` and `tls_key_file` must be set together, and
either requires `tls_ca_file`. Without `tls_ca_file` the target dials
plaintext `http://`. Key material is never logged or held on long-lived
structs; the key file is re-read on each connection attempt, so rotating
the file takes effect on the next (re)connect without a reload.

**Validation.** Every path is validated at config load with the exact
checks a dial-in `Subscribe` request would get — an unsupported path,
a mixed SAMPLE/ON_CHANGE list, or an ON_CHANGE-unsupported leaf is
rejected before the daemon starts (or before a SIGHUP reload is applied).

**Robustness.** A collector that is down (at startup or any time later)
never affects BGP operation: each target retries independently with capped
exponential backoff, logs one `warn` per outage (`debug` for repeated
retries), and surfaces its state as the `gnmi_dialout_connected{target}`
gauge. Every (re)connection starts a fresh subscription — collectors
resync from the initial snapshot exactly as a dial-in reconnect would.

**Reload.** Reload-applied: SIGHUP reconciles targets in place (removed
targets stop and their gauge series is reaped, added targets start,
changed targets redial; unchanged targets keep their live connection).

---

## `[mrt]`

Optional. Configures periodic MRT TABLE_DUMP_V2 (RFC 6396) RIB snapshots for
offline analysis and archival. Dumps can also be triggered on demand via the
gRPC `TriggerMrtDump` RPC or the `rbgp mrt-dump` CLI command.

```toml
[mrt]
output_dir = "/var/lib/rustbgpd/mrt"
dump_interval = 7200        # seconds between periodic dumps (default 7200)
compress = true             # gzip output files (default false)
file_prefix = "rib"         # filename prefix (default "rib")
```

### MRT section fields

| Field           | Type    | Required | Default  | Description                              |
|-----------------|---------|----------|----------|------------------------------------------|
| `output_dir`    | string  | yes      | --       | Directory for MRT dump files (created lazily; must be writable) |
| `dump_interval` | u64     | no       | 7200     | Seconds between periodic dumps (must be > 0) |
| `compress`      | bool    | no       | false    | Compress output files with gzip           |
| `file_prefix`   | string  | no       | `"rib"`  | Filename prefix for dump files            |

### Output files

Dump files are written atomically (temp file + rename) with collision-resistant
names:

```
{file_prefix}.{YYYYMMDD.HHMMSS}.{nanoseconds}.mrt[.gz]
```

For example: `rib.20260305.143022.123456789.mrt.gz`

### What is dumped

Each dump contains a complete `TABLE_DUMP_V2` snapshot:

| Record | Contents |
|--------|----------|
| `PEER_INDEX_TABLE` (subtype 1) | All known peers with ASN and BGP ID |
| `RIB_IPV4_UNICAST` (subtype 2) | IPv4 routes from Adj-RIB-In per peer |
| `RIB_IPV6_UNICAST` (subtype 4) | IPv6 routes from Adj-RIB-In per peer |
| `RIB_IPV4_UNICAST_ADDPATH` (subtype 8) | IPv4 routes with path IDs (RFC 8050) |
| `RIB_IPV6_UNICAST_ADDPATH` (subtype 9) | IPv6 routes with path IDs (RFC 8050) |

Routes are sourced from Adj-RIB-In (not Loc-RIB) to avoid duplicate entries
for the best-path winner. Next-hop attributes are synthesized per the MP-BGP
architecture (IPv4 `NEXT_HOP`, IPv6 `MP_REACH_NLRI`, RFC 8950
IPv4-with-IPv6-NH `MP_REACH_NLRI`).

Peer metadata is retained during Graceful Restart and LLGR transitions, so
dumps taken during a peer restart window still include correct peer entries.

The output directory is created lazily and prepared before a full RIB snapshot,
so an impossible path does not incur full-table materialization. Later failures
remain non-fatal. Delayed dumps skip missed intervals rather than replaying a
catch-up burst.

When MRT is not configured, no timer or manager task is spawned — zero
overhead.

See [ADR-0044](adr/0044-mrt-dump-export.md) for design details.

---

## `[[fib_tables]]`

Optional, repeatable. Declares ordinary Linux route tables that the
ADR-0061 general unicast FIB runtime may program. Empty by default —
route-server, route-reflector, and looking-glass deployments leave it
empty and remain control-plane-only.

```toml
[[fib_tables]]
name = "edge"
table_id = 1000
metric = 200
families = ["ipv4_unicast", "ipv6_unicast"]
allowed_peer_groups = ["transit"]
allowed_neighbors = ["198.51.100.2"]
max_routes = 1000
```

When at least one table is configured on Linux, rustbgpd starts a
level-triggered reconciler that projects Loc-RIB best routes into the
declared tables only. The actor preserves foreign kernel rows, writes
routes as `RTPROT_BGP` with the configured table and metric, drains
daemon-owned rows on coordinated shutdown, and publishes per-route
status through `RibService.ListFibRoutes` and
`rbgp rib fib`. The actor also writes a crash-recovery owned-state
file at `<runtime_state_dir>/fib-owned.json` so an ungraceful process
restart can recover routes the previous rustbgpd instance installed.

Peer and route-count guardrails are enforced before any kernel apply.
If `allowed_peer_groups` or `allowed_neighbors` is non-empty, a best
route is eligible when its source peer matches either allow-list. If
`max_routes` is set and the eligible route count for that table exceeds
the cap, the table freezes for that pass: already-owned rows stay in
place, no new growth or replacements are emitted, and over-cap candidates
that are not already owned are reported as `route_limit_exceeded`. The
rejected status list is sampled for very large over-cap tables so the cap
does not produce an unbounded API payload.
`allowed_neighbors` entries are not required to appear in `[[neighbors]]`;
this keeps the knob usable for dynamic-neighbor ranges and staged peers.

`RTPROT_BGP` is not treated as ownership proof by itself. A route that
already exists in a configured table before this daemon instance owns it
is reported as `foreign_route_exists`, even if its protocol is BGP. Crash
recovery uses the persisted owned-state file, the unchanged `[[fib_tables]]`
declaration, and an exact live-kernel value match; if any of those checks
fail, the row stays foreign. Unsupported or config-stale state files are
quarantined as `fib-owned.json.stale`. This conservative rule avoids
replacing or deleting FRR/BIRD routes in the same table and metric.
If another writer changes a row while rustbgpd owns it, the next reconcile
reports `owned_route_drifted`, releases ownership, and preserves the live
kernel row.

### Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | string | yes | -- | Operator-facing table name used in status output. Must be unique and match rustbgpd's identifier rules |
| `table_id` | u32 | yes | -- | Linux route table id. Must be unique and cannot be `0`, `252`, `253`, `254`, or `255` |
| `metric` | u32 | yes | -- | Kernel route metric / priority. Part of the daemon-owned route identity |
| `families` | string[] | no | `["ipv4_unicast", "ipv6_unicast"]` | Address families eligible for install. Only IPv4 and IPv6 unicast are accepted |
| `allowed_peer_groups` | string[] | no | `[]` | Optional source peer-group allow-list. Entries must reference existing `[peer_groups.NAME]` blocks |
| `allowed_neighbors` | string[] | no | `[]` | Optional source neighbor-address allow-list. Entries must parse as IPv4 or IPv6 addresses |
| `max_routes` | u32 | no | unset | Optional hard cap. `0` is rejected; exceeding the cap freezes existing owned rows and suppresses growth for that table |
| `maximum_paths` | u32 | no | `1` | Unicast multipath/ECMP: install up to N equal-cost next-hops per prefix as a kernel `RTA_MULTIPATH` route (ADR-0066). `1` (or unset) = single next-hop, today's behavior. Validated `>= 1`, capped at 256 |
| `maximum_paths_ebgp` | u32 | no | unset | Per-class ECMP cap for **eBGP** groups (FRR's `maximum-paths`). Overrides `maximum_paths` for eBGP best routes; falls back to `maximum_paths` then `1`. Validated `>= 1`, capped at 256 |
| `maximum_paths_ibgp` | u32 | no | unset | Per-class ECMP cap for **iBGP** groups (FRR's `maximum-paths ibgp`). Overrides `maximum_paths` for iBGP best routes; falls back to `maximum_paths` then `1`. Validated `>= 1`, capped at 256 |

**SIGHUP hot-reload** (when the FIB runtime is running): edits to
`[[fib_tables]]` — adding or removing a table, or changing a table's
`allowed_neighbors`, `allowed_peer_groups`, `max_routes`, ECMP caps, or
`families` — are applied to the running reconciler on SIGHUP **without a
restart**, provided at least one table was present at startup (so the
reconciler actor is alive). The reconciler swaps to the new desired set and
reconciles: added tables back-fill from the current best routes, removed
tables have their owned kernel rows withdrawn, and unaffected rows don't flap.
The in-memory config snapshot advances only **after** the reconciler
acknowledges the new set, so a missed apply never leaves the snapshot ahead of
the kernel.

**Restart still required to *start* the FIB subsystem from an empty config**:
if no `[[fib_tables]]` were present at startup the reconciler was never spawned,
so adding the first table needs a restart (SIGHUP logs this and leaves the
runtime unchanged). Deleting all tables at runtime is fine — the actor stays
alive but idle, and re-adding a table later hot-applies.

**gRPC / CLI runtime CRUD** (same lifecycle rules as SIGHUP): `RibService`
exposes `SetFibTable` (create-or-replace by name — the request carries the full
table definition, not a patch), `DeleteFibTable`, and `ListFibTables`, surfaced
as `rbgp fib-table {list,set,delete}`. A `set` that changes `table_id` or
`metric` for an existing name is a table-key move: the old kernel rows withdraw
and the new table back-fills. The candidate is validated against the live config
(reserved/duplicate ids, families, ECMP caps, peer-group references) before it
reaches the reconciler, applied through the same hot-reload path, and persisted
to the TOML config (atomic write) **only after** the reconciler acknowledges the
exact accepted set — and runtime CRUD is serialized with SIGHUP reloads through
one coordinator lock, so runtime and on-disk config cannot drift. The mutating
RPCs require the reconciler to be running (return `FAILED_PRECONDITION`
otherwise) and are tier `mutating`; `ListFibTables` is `sensitive_read` and also
reports whether the reconciler is running.

**Config transactions** (ADR-0076): `ConfigService.PlanConfigTransaction` can
validate a complete candidate TOML and return an optimistic runtime snapshot
token; `ApplyConfigTransaction` commits one pure runtime family at a time:
full-set `[[fib_tables]]`, full-set `[[dynamic_neighbors]]`, static
`[[neighbors]]` add/delete/modify, catalog-only
policy/neighbor-set/peer-group/global-chain changes, or pure live policy-chain
impact for static neighbors and accepted dynamic peers. Peer-group/session
reshape impact is also committable — for example a peer-group `hold_time` edit
or a static neighbor peer-group reassignment that requires the affected
sessions to be rebuilt. Static members are reconfigured in place with captured
prior configs; live dynamic sessions accepted by an affected
`[[dynamic_neighbors]]` range are gracefully reset after persist and re-accept
under the committed config on reconnect (ADR-0086). The apply path re-checks
the token under the shared runtime-config coordinator, rejects mixed or
unsupported candidates without mutation, applies live runtime state when the
family has one, persists the exact accepted candidate with an acknowledgement,
and rolls runtime state back if apply or persistence fails. Live policy-chain
impact uses Route Refresh to re-evaluate already-received routes, so every
impacted Established peer must have negotiated Route Refresh or the transaction
is rejected and rolled back. Dynamic-range peer-group reassignments and mixed
policy/session effective-impact candidates remain rejected until dedicated
executors exist.
When either the running or candidate config references external `.rpol` graphs
or `[policy.datasets]` snapshots, every full-candidate transaction family is
also rejected: the external bytes are not staged, tokened, or rollback-safe.
Use coordinated file deployment plus SIGHUP. A no-op remains a no-op, and a
pure `[[fib_tables]]` edit with unchanged external inputs remains committable
because it does not adopt the rest of the candidate snapshot.
Like SIGHUP and FIB CRUD, FIB transaction apply requires the FIB reconciler to
already be running: a daemon that started with no `[[fib_tables]]` still needs a
restart to enable the subsystem.
Operators can drive the workflow through `rbgp config plan <config.toml>`
and `rbgp config apply <config.toml> --expected-runtime-snapshot-token`;
`--json` returns the same status, section, and token fields for automation.
Plan and apply responses also carry `update_group_impact` schema version 1.
It projects each established peer and negotiated AFI/SAFI through the same
groupability classifier used by live update-group registration, assigns
deterministic plan-local group IDs, and distinguishes regroup, shared migration,
private resync, and no-op transitions. Deleted peers have an explicit `absent`
candidate state and do not count toward the projected topology or local resyncs.
New, down, or session-reshaped peers are reported as
`indeterminate_session_negotiation`; the planner never guesses future
capabilities. `local_resync` describes local outbound
re-evaluation, while `remote_route_refresh` is separate and remains false for
this outbound-only projection. Capacity is a receipt-envelope class
(`fully_shared`, `within_uniform`, `within_mixed`, `outside_measured`, or
`unknown`), not a byte, memory, or completion-time estimate.
Only the exact published 1,000-peer uniform and 900-shared/100-private
topologies receive measured capacity labels. `fully_shared` is a structural,
explicitly unmeasured label for other one-group topologies; remaining shapes are
`outside_measured`, not extrapolated. The optimistic transaction
token is also bound to the live negotiated update-group snapshot, so a session
flap, capability change, or membership change observed by Apply's mandatory
re-plan makes Apply fail with `FAILED_PRECONDITION` and requires a fresh plan.
The token is optimistic concurrency, not a session freeze after that re-plan.
For safe deploys, `ApplyConfigTransaction` also supports a confirmed-commit
mode: add `--confirm-id <id>` (and optionally `--confirm-timeout <seconds>`) to
the normal apply invocation — `rbgp config apply <config.toml>
--expected-runtime-snapshot-token <token> --confirm-id <id> --confirm-timeout
<seconds>` — or set the matching gRPC fields directly. The confirm flags are
additions; the candidate file and `--expected-runtime-snapshot-token` are still
required. The timeout defaults to 600 seconds
and is capped at 86400. The change applies immediately, then remains pending
until `rbgp config confirm <id>` (or `ConfirmConfigTransaction`) makes it
permanent. `rbgp config abort <id>` rolls it back immediately, and an
expired timer automatically re-applies the pre-commit runtime snapshot through
the same transaction executor. While a confirmed transaction is applying or
pending, persisted runtime config mutators such as static/dynamic neighbor CRUD,
policy/peer-group CRUD, FIB-table CRUD, and another config transaction are
rejected with `FAILED_PRECONDITION`; SIGHUP reload is skipped and logged until
the transaction is confirmed, aborted, or auto-reverted. Use
`rbgp config status` to inspect the redacted pending or last
confirmed-transaction state. If abort or timer rollback fails, the transaction
stays pending with the failed lifecycle result (`abort_failed` /
`auto_revert_failed`) and the mutation fence stays closed — the unconfirmed
candidate is still running and the revert journal is retained, so a mutation
accepted on top of it would be clobbered by the journal's boot revert. Resolve
it by retrying the abort, confirming the candidate, or restarting the daemon
(boot revert).

Confirm handles are operator-chosen correlation IDs. They must be non-empty, at
most 128 characters, and free of control characters; the CLI validates those
constraints before reading the candidate file or calling the daemon.

The v3 commit-confirm journal caps the current accepted normalized config it
must retain as rollback authority at 384 MiB. If that prior exceeds the cap,
confirmed apply returns `FAILED_PRECONDITION` with the actual and limit byte
counts before publishing authority or mutating peer, persisted, or runtime
state. Apply without `--confirm-id`, or reduce the canonical config size.

The confirm window is durable: before the candidate commits, the v3 writer
publishes `<runtime_state_dir>/commit-confirm-v3-prior.toml`, then
`<runtime_state_dir>/commit-confirm-v3-metadata.json`, then
`<absolute lexical config path>.commit-confirm-locator.json`. The raw prior is
the exact accepted normalized TOML. Metadata binds its provenance, digests,
length, device, and inode; the config-adjacent locator is the sole pending boot
authority. A restart checks that locator before candidate contents, verifies
the complete chain, restores the recorded target, and saves the unconfirmed
candidate as `<recorded-target>.unconfirmed`.

Confirm and successful rollback become terminal after locator removal and its
parent-directory `fsync`; later metadata/raw removal and pending-directory
`fsync` are warning-only. All pending and staging files are daemon-owned regular
files with mode `0600`, and a writer or present pending object requires
daemon-owned real parents that are not group- or world-writable. Locator
absence carries no authority and does not impose this storage policy on an
ordinary launch path.

Production reads and writes v3 authority only. Before v0.65, finish every v1/v2
transaction. Retired authority makes boot refuse untouched; recover with rustbgpd v0.64.0
or delete only after proving it terminal/intended. Retired TOML history is
ignored/retained; v2 JSON remains listable and restorable.
See `docs/OPERATIONS.md` (config transactions) for the boot-revert and storage
semantics.

```console
$ rbgp fib-table set edge --table-id 1000 --metric 200 \
    --families ipv4_unicast,ipv6_unicast --max-routes 50000
$ rbgp fib-table list
$ rbgp fib-table delete edge
```

---

## `[[evpn_instances]]`

Optional, repeatable. Declares the local L2VNI / EVPN-instance tenants
this VTEP serves (Gate 7a foundation, ADR-0052 + ADR-0055). Empty by
default — RR-only deployments leave it empty.

> By default, rustbgpd is observe-only for kernel netdevs: you provision
> the bridge and VXLAN port yourself, and the daemon probes them
> (ADR-0054 §4). See
> [docs/evpn-vtep-setup.md](evpn-vtep-setup.md) for the `ip link` recipe;
> the `bridge` / `local_vtep_ip` fields below must match. ADR-0091 is the
> explicit opt-in exception for bridge creation/adoption/reap through
> `[managed_netdevs]`; fixed-VNI VXLAN rows can also create/adopt/reap
> traditional one-VNI VXLAN devices, SVD / collect-metadata VXLAN rows can
> create/adopt/reap shared `external` / `vnifilter` VXLAN devices for
> VLAN-aware bridges, and managed VRF / L3VXLAN rows can create the VRF plus
> per-VRF L3 VXLAN topology used by `[[evpn_ip_vrfs]]`.
> ADR-0089 enables the first VLAN-aware bridge programming target through
> a local bridge-VLAN / VNI binding while keeping EVPN Ethernet Tag ID at
> `0`.

```toml
[[evpn_instances]]
vni = 100
rd = "10.0.0.1:100"
route_targets = ["65000:100"]
auto_derive_route_target = false        # derive RFC 8365 VXLAN RT from [global].asn + VNI when true
local_vtep_ip = "10.0.0.1"
bridge = "br100"                       # Linux bridge name (optional — RR-only deployments omit)
bridge_vlan = 100                      # local Linux VLAN selector for ADR-0089 VLAN-aware bridge attribution
advertise_svi_mac = false              # originate Type 2 for the bridge's own MAC (RFC 9135 §6.1)
sticky_macs = ["aa:bb:cc:dd:ee:01"]    # MACs to originate with RFC 7432 §15.4 sticky bit (ADR-0056)
ip_vrf = "vrf1"                        # link this L2VNI to a declared [[evpn_ip_vrfs]] entry (Gate 9 / ADR-0058)
apply_aliasing_ecmp = true             # program FDB nexthop groups for multi-homed Type 2 (ADR-0059)
duplicate_mac_detection = { action = "detect", window_seconds = 180, threshold = 5, recovery_seconds = 540 }
```

### Fields

| Field                 | Type     | Required | Default | Description |
|-----------------------|----------|----------|---------|-------------|
| `vni`                 | u32      | yes      | --      | 24-bit VNI (RFC 8365 §5) |
| `rd`                  | string   | yes      | --      | Route Distinguisher in RFC 4364 form (`asn:value`, `ipv4:value`, or 4-octet AS variants) |
| `route_targets`       | string[] | yes*     | `[]`    | One or more EVPN Route Targets in the same encodings. Required unless `auto_derive_route_target = true` |
| `auto_derive_route_target` | bool | no | `false` | Append the RFC 8365 §5.1.2.1 VXLAN auto-derived Route Target using `[global].asn` and `vni` (`2-octet AS only`) |
| `local_vtep_ip`       | string   | yes      | --      | Source IP for VXLAN encap on this VTEP |
| `bridge`              | string   | no       | --      | Linux bridge name for kernel reconciliation. Omit for RR-only deployments. Without `bridge_vlan`, a `Ready` L2VNI requires a non-VLAN-aware bridge with exactly one VXLAN port carrying `nolearning`; with `bridge_vlan`, it requires a traditional `vlan_filtering=1` bridge whose matching VXLAN member carries the configured VLAN |
| `bridge_vlan`         | u32      | no       | --      | Local Linux bridge VLAN selector (`1..=4094`) for ADR-0089 VLAN-aware bridge attribution. Valid only with `bridge`; this is **not** an EVPN Ethernet Tag, EVPN routes still use Ethernet Tag ID `0`, and FDB writes plus AF_BRIDGE local-MAC observations for this instance are scoped with `NDA_VLAN` |
| `advertise_svi_mac`   | bool     | no       | `false` | Originate a Type 2 route for the bridge's own MAC (RFC 9135 §6.1) when the instance has a Ready bridge report |
| `sticky_macs`         | string[] | no       | `[]`    | MAC addresses to originate with the RFC 7432 §15.4 sticky bit; SVI MAC origination honors the same list (ADR-0056) |
| `ip_vrf`              | string   | no       | --      | Name of an `[[evpn_ip_vrfs]]` entry to link this L2VNI to (Gate 9 IRB binding) |
| `apply_aliasing_ecmp` | bool     | no       | `true`  | Program ADR-0059 FDB nexthop groups for multi-homed Type 2 routes (aliasing-ECMP via `NDA_NH_ID` + `NHA_FDB`). Flip to `false` to roll this L2VNI back to single-dst FDB rows at the primary VTEP. Single-homed Type 2 entries are unaffected |
| `duplicate_mac_detection` | table | no | `{ action = "detect", window_seconds = 180, threshold = 5, recovery_seconds = 540 }` | RFC 7432 §15.1 duplicate-MAC M/N detector. `action = "detect"` records threshold crossings only; `action = "suppress_local"` additionally withdraws/suppresses locally-originated Type 2 MAC-only and MAC+IP routes for the offending `(VNI, MAC)` until `recovery_seconds` elapses |

### Validation

- The combined table enforces uniqueness on both `vni` and `rd` —
  duplicates on either column reject config load.
- `bridge` (when set) must reference a Linux bridge that already exists
  or is declared in `[managed_netdevs]` for ADR-0091 bridge lifecycle
  ownership. ADR-0091 bridge, fixed-VNI `[[managed_netdevs.vxlans]]`,
  `[[managed_netdevs.svd_vxlans]]`, VRF, and L3VXLAN lifecycle now ship
  (create/adopt/reap).
- `bridge_vlan` (when set) must be in `1..=4094` and requires
  `bridge`. At runtime it selects the ADR-0089 VLAN-aware path: the
  observed bridge must have `vlan_filtering=1`, the configured VLAN
  present on the bridge, and exactly one matching VXLAN target. A
  target can be either a fixed-VNI VXLAN member carrying the VLAN, or
  a collect-metadata / SVD VXLAN member whose VLAN tunnel mapping ties
  that VLAN to the instance VNI. Without `bridge_vlan`, a
  `vlan_filtering=1` bridge remains `NotReady`.
- `advertise_svi_mac = true` is inert until the instance has a Ready
  bridge report with a bridge MAC; configs without `bridge` are accepted
  but originate nothing.
- `route_targets` may be omitted or empty only when
  `auto_derive_route_target = true`; otherwise at least one explicit RT is
  required.
- `auto_derive_route_target = true` requires `[global].asn <= 65535`. RFC
  8365 §5.1.2.1 does not define an auto-derived VXLAN RT for 4-octet ASNs,
  so those deployments must configure `route_targets` manually.
- `ip_vrf` (when set) must name an `[[evpn_ip_vrfs]]` entry declared
  in the same config.
- `duplicate_mac_detection.window_seconds`, `threshold`, and
  `recovery_seconds` must all be greater than zero.
- `duplicate_mac_detection.recovery_seconds` must be no greater than
  31,536,000 seconds (365 days).
- Same VNI must not appear in multiple `[[ethernet_segments]]`
  `member_vnis` lists until per-port learned disambiguation is plumbed.

The auto-derived RT form depends on the VNI's scope:

- **L2VNI / MAC-VRF** (`[[evpn_instances]]`): the RFC 8365 §5.1.2.1 *opaque*
  2-octet-AS RT with local-admin value `0x10000000 | vni`. For example
  `[global].asn = 65000`, `vni = 100` → `65000:268435556`.
- **L3VNI / IP-VRF** (`[[evpn_ip_vrfs]]`): a plain `AS:VNI` 2-octet-AS RT.
  For example `[global].asn = 65000`, `vni = 100` → `65000:100`.

Explicit `route_targets` are preserved; when auto-derive is also enabled the
derived RT is appended and duplicates are deduped during config resolution.

**Cross-vendor interop.** The two forms exist because that is what FRR (and
Cumulus/NVIDIA) actually put on the wire:

- For the **L3VNI / IP-VRF** RT, FRR's tenant-VRF auto-RT is `AS:VNI`
  regardless of any knob, so rustbgpd's `AS:VNI` form imports against a
  default FRR L3VNI peer with no extra configuration. (Validated by the
  M39b interop smoke.)
- For the **L2VNI / MAC-VRF** RT, rustbgpd uses the RFC 8365 opaque form,
  which matches FRR **only** when FRR is configured with `autort
  rfc8365-compatible` (under `address-family l2vpn evpn`). FRR's *default*
  L2VNI autort is `AS:VNI`, which would not match. rustbgpd-to-rustbgpd
  fabrics always agree. When peering an L2VNI with a vendor whose auto-RT
  form you are unsure of, configure `route_targets` explicitly on both ends.

### Duplicate-MAC Detection And Local Suppression

RFC 7432 §15.1 describes duplicate-MAC detection as `N` mobility
events within `M` seconds, with defaults `N = 5` and `M = 180s`.
rustbgpd applies that window per `(VNI, MAC)` inside the local
originator.

Default behavior is detection-only:

```toml
duplicate_mac_detection = { action = "detect" }
```

With `action = "suppress_local"`, crossing the threshold withdraws any
locally-originated Type 2 routes for that MAC on this VNI (MAC-only and
MAC+IP), suppresses future local originations while the quarantine is
active, and automatically retries after `recovery_seconds`:

```toml
duplicate_mac_detection = { action = "suppress_local", window_seconds = 180, threshold = 5, recovery_seconds = 540 }
```

This first action slice is intentionally local-origin scoped. The EVPN
Loc-RIB, route-reflector behavior, `ListEvpnRoutes`, and receive-side
dataplane projection remain visible/unchanged; full remote-route
processing suppression and dataplane loop-protection are tracked as
follow-up work.

### Aliasing-ECMP off-switch behavior

`apply_aliasing_ecmp = false` routes multi-homed Type 2 entries on the
target L2VNI through the single-dst FDB path (primary VTEP only, no
kernel-side ECMP); other L2VNIs in the same daemon are unaffected.

**Runtime mutation and reload behavior**: ADR-0063's coordinator
live-commits supported `[[evpn_instances]]` changes through both
`EvpnService.ApplyEvpnRuntime` and SIGHUP reload. A redefine, including
field flips such as `bridge_vlan` or `apply_aliasing_ecmp`, re-derives per-VNI dataplane
state via the `FdbNhg → SingleDst` transition. Supported shapes include
single L2VNI/IP-VRF/Ethernet-Segment add/delete/redefine, additive
build-up, atomic tenant teardown, `ip_vrf` relink, and decomposable mixed edits
ordered as deletes -> redefines -> `ip_vrf` relinks -> adds. L3VNI/device/table
IP-VRF identity changes remain restart-required by design. Unsupported
dependency cycles fail closed before commit; residual mid-sequence convergence
failures fail-stop after any earlier primitive generations that already
committed.

**Restart edge case**: if you flip `apply_aliasing_ecmp = false` and
restart the daemon while tagged FDB nexthop groups from the prior run
are still in the kernel, the orphaned tagged FDB rows remain bound to
the stale `nh_id` until the next periodic drift cycle cleans them up
(≤ 60 s, ADR-0059 slice 3.5 PR 2).

---

## `[[ethernet_segments]]`

Optional, repeatable. Declares local Ethernet Segments for active-active
multi-homing (Gate 8 + 8b, RFC 7432 §8 + RFC 8584 + ADR-0057). Empty by
default — single-homed VTEPs leave it empty.

```toml
[[ethernet_segments]]
esi = "00:00:00:00:00:00:00:00:00:01"          # 10-byte ESI (Type 0 here; Types 1–5 also accepted)
member_vnis = [100, 200]                       # L2VNIs this ES is reachable on
df_preference = 32768                          # RFC 9785 preference; default/HRW require this default
df_algorithm = "default-modulo"                # default-modulo, highest-random-weight, highest-preference, or lowest-preference
redundancy_mode = "all-active"                 # "all-active" or "single-active"
originator_ip = "10.0.0.1"                     # source IP used for Type 1/4 origination
```

### Fields

| Field           | Type     | Required | Default       | Description |
|-----------------|----------|----------|---------------|-------------|
| `esi`           | string   | yes      | --            | 10-byte non-zero ESI in colon-separated hex (RFC 7432 §5). The all-zero Type 0 single-homed sentinel is rejected; non-zero Type 0 and Types 1–5 are accepted. |
| `member_vnis`   | u32[]    | yes      | --            | L2VNIs this segment is reachable on. Each must match a configured `[[evpn_instances]].vni` |
| `df_preference` | u32      | no       | `32768`       | RFC 9785 preference value for `"highest-preference"` / `"lowest-preference"` (`0..=65535`). Default-modulo and HRW ignore preference, so only the default is accepted for those algorithms |
| `df_algorithm`  | string   | no       | `"default-modulo"` | `"default-modulo"` (RFC 7432 §8.5 service carving), `"highest-random-weight"` (RFC 8584 §3.2), `"highest-preference"` or `"lowest-preference"` (RFC 9785) |
| `df_dont_preempt` | bool   | no       | `false`       | RFC 9785 Don't-Preempt (non-revertive): when `true`, advertise DP=1 in the Type 4 DF Election extcomm. Only valid with `"highest-preference"` / `"lowest-preference"` — rejected for default-modulo / HRW. Origination + parse only today: the DP bit is not yet an election input (stateful non-revertive election is deferred), so a peer's DP=1 does not currently change which PE rustbgpd elects. |
| `redundancy_mode` | string | no       | `"all-active"` | `"all-active"` sets the ESI Label extcomm Single-Active flag to 0 and allows receiver-side aliasing ECMP. `"single-active"` sets the flag to 1, suppresses all-active aliasing ECMP for remote single-active ES reachability, and enables the receive-side backup-path pre-install path from ADR-0083 |
| `originator_ip` | string   | yes      | --            | Source IP carried in Type 1/4 origination. Usually equals a member VNI's `local_vtep_ip` |
| `interface`     | string   | no       | --            | ADR-0085 attachment-circuit link binding: name of the local link whose carrier drives this ES's link drain. When set, carrier loss on the link drains the segment automatically |
| `recovery_delay_secs` | u64 | no       | `30`          | ADR-0085 hold-off (seconds, `0..=3600`) to wait after carrier returns before releasing the link drain. Only valid with `interface` — rejected without it |

### What gets originated

When `[[ethernet_segments]]` is non-empty and the EVPN reconcile actor
is running, each segment originates:

- **Type 4 (ES route)** — one per `[[ethernet_segments]]` block, with
  ES-Import Route Target derived from the ESI per RFC 7432 §7.6.
- **Type 1 EAD-per-ES** — one per ES with `ethernet_tag = MAX_ET` and
  the ESI label (assigned by `EsiLabelAllocator`, ADR-0057 §6) in the
  ESI Label extended community.
- **Type 1 EAD-per-EVI** — one per `(ES, member_vni)` pair, with
  `ethernet_tag = 0` (RFC 7432 §6.1 VLAN-based service) and the member
  VNI in the route's label field (RFC 8365 §5.1.3). The per-VNI RD
  keeps the routes distinct.

The DF election runs on the union of locally configured ES and
remote Type 4 routes for the same ESI; the elected DF role drives
Type 2 origination ESI tagging and the optional BUM-suppression
filter (see the top-level `apply_bum_enforcement` key).

SIGHUP reload and `EvpnService.ApplyEvpnRuntime` can live-commit a single
Ethernet Segment add, delete, or redefine when the segment actor exists,
additive build-up, and dropping an Ethernet Segment (delete or member-shrink)
as part of an atomic tenant teardown alongside its member L2VNI. Mixed edits
that can be decomposed into the supported primitive order also commit live;
unsupported dependency cycles fail closed before commit.

---

## `[[evpn_ip_vrfs]]`

Optional, repeatable. Declares the local IP-VRF / L3VNI tenants this VTEP
serves under the RFC 9136 §4.4.2 symmetric Interface-less IRB model
(Gate 9, ADR-0058). Empty by default — L2-only VTEPs and RR-only
deployments leave it empty.

> rustbgpd is observe-only for kernel netdevs: you provision the VRF and
> L3 VXLAN devices yourself, and the daemon probes them against the seven
> ADR-0058 §3 predicates. See [docs/evpn-vtep-setup.md](evpn-vtep-setup.md)
> for the `ip link` recipe the fields below must match.

The daemon parses and validates this block, builds an `IpVrfTable`,
runs the per-pass `IpVrfStatus` readiness probe (the seven ADR-0058
§3 predicates), originates Type 5 routes from observed local
forwarding routes when the IP-VRF is `Ready`, imports remote Type 5
routes through the transactional `L3OwnedState` model, and programs
kernel routes + L3 neighbor + L3VXLAN FDB rows atomically with
four-phase apply ordering (route-remove → resolution-add → route-add
→ resolution-remove) and Router MAC conflict detection. Operators
read readiness, originated-route count, and installed-route count
via `rbgp evpn vrfs [NAME]` and the `EvpnService.ListIpVrfs` /
`EvpnService.GetIpVrf` gRPC RPCs. Sub-second tenant withdraw is
driven by `RTNLGRP_IPV4_ROUTE` / `RTNLGRP_IPV6_ROUTE` multicast.

```toml
[[evpn_ip_vrfs]]
name = "tenant-blue"               # operator-facing handle
vni = 5000                         # L3VNI (1..=16_777_215)
rd = "65000:5000"                  # Route Distinguisher
route_targets = ["65000:5000"]     # bidirectional RTs (non-empty)
auto_derive_route_target = false   # derive AS:VNI RT from [global].asn + L3VNI when true (FRR-compatible)
local_vtep_ip = "10.0.0.1"         # VXLAN source IP for outbound Type 5
router_mac = "02:00:00:00:00:01"   # Router MAC ext-community value
vrf_device = "vrf-blue"            # Linux VRF device (observe-only)
l3vxlan_device = "vni5000"         # Linux L3 VXLAN device (observe-only)
table_id = 5000                    # VRF route table id
overlay_index_mode = "interface_less" # "interface_less", "gateway_ip", or "esi" (ADR-0087)
# overlay_index_esi = "00:00:00:00:00:00:00:00:00:01" # required when mode = "esi"
# overlay_index_mac = "02:aa:bb:cc:dd:ee"             # required when mode = "esi"
# overlay_index_l2vni = 100                            # required for ESI mode only when multiple L2VNIs link here

# An `[[evpn_instances]]` entry binds to this IP-VRF by name.
[[evpn_instances]]
vni = 100
rd = "65000:100"
route_targets = ["65000:100"]
local_vtep_ip = "10.0.0.1"
ip_vrf = "tenant-blue"             # optional — empty means L2-only
```

### IP-VRF fields

| Field            | Type      | Required | Default | Description |
|------------------|-----------|----------|---------|-------------|
| `name`           | string    | yes      | --      | Operator handle; `^[a-zA-Z][a-zA-Z0-9_-]*$`, unique across `[[evpn_ip_vrfs]]` |
| `vni`            | u32       | yes      | --      | L3VNI in `1..=16_777_215`; must not collide with any `[[evpn_instances]]` VNI |
| `rd`             | string    | yes      | --      | Route Distinguisher (`asn:value` or `ipv4:value`) |
| `route_targets`  | [string]  | yes*     | `[]`    | Bidirectional RTs applied to import and export. Required unless `auto_derive_route_target = true` |
| `auto_derive_route_target` | bool | no | `false` | Append the auto-derived L3VNI RT as plain `AS:VNI` from `[global].asn` and the L3VNI — matches FRR's default tenant-VRF auto-RT (`2-octet AS only`) |
| `local_vtep_ip`  | string    | yes      | --      | Unicast VTEP source IP for outbound Type 5 `NEXT_HOP` |
| `router_mac`     | string    | yes      | --      | Unicast non-zero MAC (`aa:bb:cc:dd:ee:ff`) advertised via the RFC 9135 §4.2 / RFC 9136 Router MAC extended community |
| `vrf_device`     | string    | yes      | --      | Linux VRF device name (operator-managed, observe-only) |
| `l3vxlan_device` | string    | yes      | --      | Linux L3 VXLAN device name (operator-managed, observe-only) |
| `table_id`       | u32       | yes      | --      | VRF route table id (> 0); cross-checked against `vrf_device`'s `IFLA_VRF_TABLE` |
| `overlay_index_mode` | string | no      | `"interface_less"` | Outbound Type 5 overlay-index shape (ADR-0087). `"interface_less"` (RFC 9136 §4.4.2) keeps the Gateway Address zero + Router's MAC extcomm. `"gateway_ip"` (RFC 9136 §4.1/§4.2) originates a route whose kernel via lands on a connected subnet of this VRF with that via in the Gateway Address and no Router's MAC extcomm; routes without an eligible via fall back to interface-less. `"esi"` (RFC 9136 §4.3) originates with a configured non-zero ESI, zero Gateway Address, and `overlay_index_mac` as the Router MAC extcomm. `"gateway_ip"` and `"esi"` require at least one `ip_vrf`-linked L2VNI |
| `overlay_index_esi` | string | `esi` only | -- | Non-zero ESI (`xx:xx:xx:xx:xx:xx:xx:xx:xx:xx`) used as the Type 5 overlay index when `overlay_index_mode = "esi"`; must match a configured `[[ethernet_segments]].esi` |
| `overlay_index_mac` | string | `esi` only | -- | Unicast non-zero virtual/transit MAC advertised as the Router MAC extcomm when `overlay_index_mode = "esi"` |
| `overlay_index_l2vni` | u32 | conditional | -- | L2VNI disambiguator for `overlay_index_mode = "esi"` when multiple `[[evpn_instances]]` entries link to this IP-VRF; the selected L2VNI must be linked to this IP-VRF and be a member of `overlay_index_esi` |

### L2VNI binding

`[[evpn_instances]].ip_vrf` is an optional string that names an
`[[evpn_ip_vrfs]]` entry. Empty / unset leaves that L2VNI as
bridging-only. Validation rejects a name that does not resolve to any
declared IP-VRF.

### Readiness predicates

The reconcile actor maps each IP-VRF against its kernel snapshot every
pass. ADR-0058 §3 defines seven predicates that must all hold for the
IP-VRF to be `Ready`:

1. `vrf_device` exists and is administratively UP.
2. `vrf_device`'s `IFLA_VRF_TABLE` equals `table_id`.
3. `l3vxlan_device` exists and is administratively UP.
4. `l3vxlan_device`'s `IFLA_VXLAN_ID` equals the configured L3VNI.
5. `l3vxlan_device`'s `IFLA_VXLAN_LOCAL` (or `IFLA_VXLAN_LOCAL6`) equals
   `local_vtep_ip`.
6. `l3vxlan_device`'s `IFLA_MASTER` points to `vrf_device`.
7. `l3vxlan_device`'s link-layer address equals the configured
   `router_mac`.

`NotReady` results enumerate every failing predicate; the actor logs
the transition once per state change rather than every pass.

### Validation rules (Gate 9 foundation)

- `name` matches `^[a-zA-Z][a-zA-Z0-9_-]*$` and is unique across `[[evpn_ip_vrfs]]`.
- `vni` is in `1..=16_777_215` and does not collide with any `[[evpn_instances]]` VNI.
- `rd` parses as `asn:value` or `ipv4:value`.
- `route_targets` is non-empty and every entry parses unless
  `auto_derive_route_target = true`.
- `auto_derive_route_target = true` requires `[global].asn <= 65535`; 4-octet
  ASNs must configure `route_targets` manually.
- `local_vtep_ip` is a valid unicast IP (rejects unspecified / multicast / loopback).
- `router_mac` is a unicast non-zero MAC.
- `vrf_device` and `l3vxlan_device` are non-blank.
- `table_id` is `> 0`.
- `overlay_index_mode` is `"interface_less"` (default), `"gateway_ip"`, or
  `"esi"`. `"gateway_ip"` is rejected at load unless at least one
  `[[evpn_instances]]` links to this IP-VRF via `ip_vrf` — the GW-IP
  receive side scopes its recursive Type 2 lookup to the linked
  L2VNIs, so a `gateway_ip` VRF with no L2VNI link could never
  originate a resolvable route (ADR-0087). `"esi"` also requires at least one
  linked L2VNI plus `overlay_index_esi` and `overlay_index_mac`.
- `overlay_index_esi`, `overlay_index_mac`, and `overlay_index_l2vni` are valid
  only when `overlay_index_mode = "esi"`. The ESI must be non-zero and match a
  configured `[[ethernet_segments]].esi`; the MAC must be unicast and non-zero.
  If exactly one L2VNI links to the IP-VRF, that L2VNI is selected
  automatically. If multiple L2VNIs link to the IP-VRF, `overlay_index_l2vni`
  is required and must both link to the IP-VRF and appear in the selected
  Ethernet Segment's `member_vnis`.
- Every `[[evpn_instances]].ip_vrf` resolves to a declared IP-VRF.
- `[[evpn_ip_vrfs]]` follows the ADR-0063 coordinator lifecycle.
  SIGHUP and `EvpnService.ApplyEvpnRuntime` can live-commit a single
  IP-VRF add, standalone delete, or redefine with unchanged
  L3VNI/device/table identity, and an atomic tenant teardown that drops a
  linked IP-VRF together with its L2VNI (and any Ethernet Segment) in one
  pass. `ip_vrf` relink and decomposable mixed edits ordered as deletes ->
  redefines -> `ip_vrf` relinks -> adds commit live. L3VNI/device/table IP-VRF
  identity changes remain restart-required shapes.

### GW-IP overlay-index origination (`overlay_index_mode = "gateway_ip"`)

By default (`"interface_less"`) every originated Type 5 carries
Gateway Address zero and the Router's MAC extended community —
receivers reach the prefix's VTEP and resolve the inner MAC from that
extcomm (RFC 9136 §4.4.2). With `"gateway_ip"` (RFC 9136 §4.1/§4.2,
ADR-0087), a kernel route whose via (`ip route add <prefix> via <gw>`)
lands inside a connected subnet of the VRF is originated with that via
in the Gateway Address and **no** Router's MAC extcomm; receivers
resolve the gateway recursively through its Type 2 MAC/IP route and
forward straight to wherever the gateway host lives. When the gateway
host moves, its Type 2 alone re-converges every prefix that points at
it.

- The via must land on a `Connected` (kernel) prefix of the same VRF
  with prefix length > 0 and be a usable gateway host. Ordinary IPv4
  subnet network and directed-broadcast addresses fall back to the
  interface-less shape; `/31` point-to-point endpoints and `/32` host
  routes are eligible. An off-subnet via (no Type 2 will ever name it)
  falls back too, as does a route with no via.
- The companion Type 2 is a dependency, not a precondition: rustbgpd
  originates the Type 5 immediately, and receivers hold it unresolved
  (surfaced via the `unresolved_overlay_index_gateway` drop counter)
  until the Type 2 arrives. The L3VNI stays in the label slot in both
  modes (deviating from the RFC 9136 §3.1 SHOULD-zero — our own
  receive side and FRR both keep it).
- A via change re-originates in place (same route key, new Gateway
  Address) — one UPDATE, no withdraw/announce pulse.

### ESI overlay-index origination (`overlay_index_mode = "esi"`)

With `"esi"` (RFC 9136 §4.3), every locally originated Type 5 for that
IP-VRF carries:

- the configured non-zero `overlay_index_esi` as the Type 5 ESI;
- Gateway Address zero, so the route carries exactly one overlay index;
- the IP-VRF's L3VNI in the label slot, matching the shipped
  interface-less and GW-IP shapes;
- Router MAC extcomm set to `overlay_index_mac`, which names the virtual
  appliance / transit-switch MAC rather than the PE/NVE `router_mac`.

This mode is for locally attached multi-homed gateway designs where receivers
resolve the ESI through Ethernet A-D state. rustbgpd also ships bounded
receive-side ESI protected recursion: a non-zero-ESI Type 5 imports through
scoped EAD-per-EVI state when the candidate set is either exactly one
single-active remote VTEP or a valid two-or-more-member all-active target set.
Unsupported, ambiguous, mixed-signal, or incomplete ESI recursion still drops
fail-closed through bounded remote-prefix drop reasons. Existing receive-side
GW-IP protected recursion is unchanged.

See [ADR-0058](adr/0058-evpn-gate-9-irb-l3vni.md) and
[ADR-0087](adr/0087-evpn-type5-gateway-ip-overlay-index-origination.md)
for the design rationale.

---

## `[managed_netdevs]`

ADR-0091 managed EVPN netdevs are opt-in and class-scoped. The current
surface accepts bridge rows, fixed-VNI VXLAN rows, SVD / collect-metadata
VXLAN rows, VRF rows, L3VXLAN rows, and VLAN upper rows, derives durable Linux
altname ownership stamps, and reports status through
`EvpnService.ListManagedNetdevs` / `rbgp evpn managed-netdevs`. Bridge,
fixed-VNI VXLAN, SVD VXLAN, VRF, L3VXLAN, and VLAN
upper rows are active lifecycle intent: the dataplane actor creates missing
links, stamps them with the derived altname, treats exact stamped links as
crash-restart adoption, and reaps exact same-owner orphans when the config
keeps the owner token but removes the row. Reap order is dependency-aware:
VLAN upper rows are removed before their bridge, L3VXLAN rows are removed
before their VRF, and a stamped VRF is never removed while slave links remain
attached.

Any `[managed_netdevs]` add/remove/change is restart-required in this
tranche for SIGHUP, config transactions, gNMI Set, and
`EvpnService.ApplyEvpnRuntime`.

```toml
[managed_netdevs]
owner_token = "leaf-1"             # ASCII letters/digits/_/./-, <= 63 bytes

[[managed_netdevs.bridges]]
name = "br100"                     # Linux ifname, <= 15 bytes
vlan_filtering = true              # protected bridge attribute

[[managed_netdevs.vxlans]]
name = "vxlan100"                  # Linux ifname, <= 15 bytes
vni = 100                          # fixed VNI, 1..=16_777_215
local = "10.0.0.1"                 # VXLAN local source IP
dstport = 4789                     # optional; defaults to IANA VXLAN port
bridge = "br100"                   # desired bridge master
learning = false                   # optional default; true is rejected

[[managed_netdevs.svd_vxlans]]
name = "vxlan-svd"                 # Linux ifname, <= 15 bytes
local = "10.0.0.1"                 # optional VXLAN local source IP
dstport = 4789                     # optional; defaults to IANA VXLAN port
bridge = "br100"                   # desired VLAN-aware bridge master
learning = false                   # optional default; true is rejected

[[managed_netdevs.vlan_uppers]]
name = "br100.10"                  # Linux ifname, <= 15 bytes
bridge = "br100"                   # parent bridge
vlan = 10                          # VLAN id, 1..=4094

[[managed_netdevs.vrfs]]
name = "vrf100"                    # Linux ifname, <= 15 bytes
table_id = 100                     # Linux VRF table id, non-zero

[[managed_netdevs.l3vxlans]]
name = "l3vxlan100"                # Linux ifname, <= 15 bytes
vni = 100                          # L3VNI, 1..=16_777_215
local = "10.0.0.1"                 # VXLAN local source IP
dstport = 4789                     # optional; defaults to IANA VXLAN port
vrf = "vrf100"                     # desired VRF master
router_mac = "02:00:00:00:00:01"   # non-zero unicast Router MAC
learning = false                   # optional default; true is rejected
```

The VXLAN `bridge` field names the desired bridge master. It may reference a
managed `[[managed_netdevs.bridges]]` row or an operator-provisioned bridge;
either way it is bound by name. The VXLAN lifecycle only creates the VXLAN
after that name resolves to a Linux bridge; an absent bridge or same-name
non-bridge link makes the create operation fail closed rather than attach to an
unexpected master. If the named bridge also has a managed bridge row and is
foreign or owned-unsafe, that state is reported on the bridge row while the
EVPN L2 readiness check remains fail-closed until the topology matches config.
SVD VXLAN rows derive their bridge VLAN / VNI bindings from configured
`[[evpn_instances]]` rows that name the same `bridge` and set `bridge_vlan`.
The lifecycle creates an `external` / `vnifilter` / `nolearning` VXLAN, enables
bridge `vlan_tunnel` on the VXLAN port, and programs each bridge VLAN tunnel
mapping (`bridge VLAN -> VNI`) from those EVPN instance rows.

The derived ownership stamps are:

```text
rustbgpd:bridge:<owner_token>:<bridge_name>
rustbgpd:vxlan:<owner_token>:<vxlan_name>
rustbgpd:svd-vxlan:<owner_token>:<svd_vxlan_name>
rustbgpd:vlan-upper:<owner_token>:<vlan_upper_name>
rustbgpd:vrf:<owner_token>:<vrf_name>
rustbgpd:l3vxlan:<owner_token>:<l3vxlan_name>
```

Validation rejects managed rows without `owner_token`, duplicate managed
netdev names across bridge, VXLAN, SVD VXLAN, VLAN upper, VRF, and L3VXLAN
rows, invalid Linux-style link names (`.`, `..`, spaces, or names over 15
bytes), invalid owner tokens, and derived stamps longer than Linux's 127-byte
altname limit.
VXLAN validation also rejects invalid VNIs (outside `1..=16_777_215`), a
duplicate `vni` shared by two VXLAN rows, `dstport = 0`, and
`learning = true`. SVD VXLAN validation rejects `dstport = 0`,
`learning = true`, duplicate SVD bridges, and any row whose `bridge` does not
match at least one configured `[[evpn_instances]]` row with `bridge_vlan`.
VLAN upper validation rejects invalid VLAN ids (outside
`1..=4094`), duplicate `(bridge, vlan)` helper rows, and any row whose
`(bridge, vlan)` pair does not match a configured `[[evpn_instances]]` row
with the same `bridge` and `bridge_vlan`. VRF validation rejects
`table_id = 0`, the Linux reserved tables `252`, `253`, `254`, and `255`
(compat/default/main/local), duplicate managed VRF table ids, and a managed
VRF `table_id` that collides with a `[[fib_tables]]` `table_id`. L3VXLAN
validation rejects invalid VNIs, duplicate managed L3VXLAN VNIs, `dstport = 0`,
`learning = true`, a `vrf` value that does not reference a configured
`[[managed_netdevs.vrfs]]` row, a missing, multicast, or all-zero
`router_mac`, and an L3VXLAN `vni` (L3VNI) that equals any
`[[managed_netdevs.vxlans]]` `vni` (L2VNI) — the L3VNI and L2VNI must be
distinct. If a managed VRF name matches an `[[evpn_ip_vrfs]].vrf_device`, the
managed `table_id` must equal that IP-VRF's table id. If a managed L3VXLAN name
matches an `[[evpn_ip_vrfs]].l3vxlan_device`, the managed `vni`, `local`, and
`router_mac` must equal the IP-VRF's L3VNI, local VTEP IP, and Router MAC.

rustbgpd preserves foreign links. A same-name bridge, VXLAN, VLAN upper, VRF,
SVD VXLAN, or L3VXLAN without the exact ownership stamp is reported
`foreign-present` and is not modified. A link with the expected stamp plus any
other rustbgpd stamp, a wrong owner stamp, a stamp/name mismatch, or
protected-attribute drift is reported `owned-unsafe` and is not repaired or
deleted by v1. A
rustbgpd-stamped link whose stamp class does not match its kind — for example a
bridge-kind link carrying only a `rustbgpd:vxlan:...` stamp, or a VXLAN-kind
link carrying only a `rustbgpd:bridge:...` stamp — is also reported
`owned-unsafe` (ADR-0091 Decision 6); it is never silently hidden from status.
Protected attributes are: bridge `vlan_filtering`; fixed-VNI VXLAN `vni`,
`local`, `dstport`, `learning`, `collect-metadata`, `vnifilter`, and `bridge`
attachment; SVD VXLAN fixed-VNI absence, optional `local`, `dstport`,
`learning`, `collect-metadata`, `vnifilter`, `bridge` attachment, and
bridge VLAN/tunnel mappings; VLAN upper `bridge`, `vlan`, and link-up state;
VRF `table_id`; and L3VXLAN `vni`, `local`, `dstport`, `learning`,
`collect-metadata`, `vnifilter`, `vrf` master, and `router_mac`. The bounded Prometheus gauge
`evpn_managed_netdev_state{class,name,desired,state}` mirrors the latest
reported state for alerting; detailed reason text is available through
`ListManagedNetdevs` / `rbgp evpn managed-netdevs`.

Reaping is equally conservative. When the owner token stays but a bridge,
fixed-VNI VXLAN, SVD VXLAN, VLAN upper, VRF, or L3VXLAN row is removed, only
an exact same-owner stamped orphan for that class is reaped. A de-configured
rustbgpd-stamped fixed-VNI VXLAN or L3VXLAN that has drifted into a
collect-metadata or vnifilter mode — modes the fixed-VNI lifecycles never
create — is preserved (`owned-unsafe`), not reaped.

Status states:

| State | Meaning |
|-------|---------|
| `desired-absent` | Configured bridge, VXLAN, SVD VXLAN, VLAN upper, VRF, or L3VXLAN is not present in the kernel snapshot |
| `foreign-present` | Same-name link exists without the expected rustbgpd ownership stamp |
| `owned-unsafe` | Link carries a rustbgpd stamp that is not the expected one (including a stamp whose class does not match the link kind), or a protected attribute does not match config |
| `owned-safe` | Expected stamp and protected attributes match |
| `orphaned` | A rustbgpd-stamped link exists with no desired config row |
| `unknown` | No dataplane status snapshot has been published yet, or the link dump failed |

---

## `[event_history]`

Durable event-history outbox (ADR-0072). A daemon-local SQLite WAL
store that survives daemon restart with a monotonic `event_id`
cursor. External collectors bridge to their own bus (Kafka, NATS,
Vector, journald, custom) over the existing gRPC event-stream
RPCs; rustbgpd itself does not try to be an event bus.

**Opt-in — default off as of v0.32.0.** The outbox is disabled by
default; operators who want restart-safe event replay set
`enabled = true` and restart. It is off by default because v0.32.0
benchmarking measured a material always-on cost (~62 MB RSS and roughly
double the peak CPU at 2p/100k); a routing daemon should be lean by
default. While disabled, `SubscribeFromEvent` and gNMI `Subscribe
ON_CHANGE` return `FAILED_PRECONDITION`; the live `WatchEvents` /
`WatchRoutes` / `List*Events` surfaces are unaffected. When enabled, the
outbox is bounded by a hard `max_events` count cap plus a `max_bytes`
retention trigger. SQLite reuses freed pages after DELETE and does not
guarantee that the main database file immediately shrinks without a
future compaction pass, so `max_bytes` is an operational target rather
than a strict filesystem ceiling in v1.

All fields are restart-required; see
[reload-matrix.md](reload-matrix.md#event_history-adr-0072) for
the per-field classification.

```toml
[event_history]
enabled = false                 # default (v0.32.0); set true for durable event replay
required = false                # if true, daemon fails to start when DB unrecoverable
path = ""                       # relative to runtime_state_dir; "" = events.db
max_events = 100_000            # hard count cap
max_bytes = 256_000_000         # byte retention target (events.db + WAL)
synchronous = "full"            # full = fsync per commit; normal trades crash window for throughput
overflow = "drop"               # v1 only supports "drop"; "block" reserved for a future ADR
queue_capacity = 4096           # per-producer mpsc capacity
batch_size = 1024               # batch-commit size threshold
batch_interval_ms = 50          # batch-commit time threshold
```

### Recovery and degraded health

When the events DB fails to open or is corrupted:

- The bad file is renamed to `events.db.stale` (matches the
  `*.json.stale` convention from `fib-owned.json`).
- The allocator anchor is recovered via authoritative DB metadata:
  primary DB metadata, then quarantine fallback. `events.last_id` is
  written as a diagnostic hint, but it may lag committed events and is
  not used to resume allocation in v1.
- If both authoritative sources fail AND prior allocation evidence
  exists (`events.db.stale` or `events.last_id`), EHM enters
  pass-through (`required = false`) or refuses to start
  (`required = true`). The allocator never restarts at 1 silently.
- `bgp_event_outbox_degraded` flips to `1` and does not auto-
  clear in v1; operator restarts to clear.

### Best-effort under overload

On a full producer queue, EHM drops the event, increments
`bgp_event_outbox_dropped_total{category, reason="queue_full"}`,
and flips the degraded flag. Drops are **observable but lie
outside the committed cursor sequence by design**. The outbox is
not a compliance-grade audit log; operators wanting that should
treat it as a transport to their external bus, which is the
system of record.

### External-bus integration

The documented pattern is `SubscribeFromEvent(from_event_id)` —
a server-side replay-then-live join over the durable outbox.
Cursor semantics on `from_event_id`:

- absent ⇒ live-only (no replay), like `WatchEvents`.
- `0` ⇒ replay everything retained, then live (fresh-collector
  case).
- `N > 0` ⇒ replay events with `event_id > N`, then live (the
  normal reconnect case).

When the requested cursor is older than the retention floor,
the server emits a leading `StreamLagEvent` with the missed
count over the global committed stream (not the filtered
subset) and then resumes replay from the earliest retained
event. The `bgp_event_outbox_cursor_gap_total` counter
tracks how often that fires — alert on non-zero to know your
retention is undersized for the collector reconnect SLA.

The CLI `rbgp events watch --from-event-id <N>` drives
the same RPC and is mutually exclusive with `--backfill`
(`--backfill` replays the daemon's process-local route ring,
which resets on restart; `--from-event-id` replays the
durable outbox, which survives restart).

`examples/event-bridge/` is the reference workspace binary
that streams `BgpEvent` as JSON-lines to stdout. Operators
copy it and replace the stdout writer with their Kafka /
NATS / Vector / journald sink, then persist
`last_seen_event_id` after their downstream sink confirms
durable receipt. See `OPERATIONS.md` "Durable Event Cursor"
for the alert + sizing playbook.

When `enabled = false`, when EHM failed to start with
`required = false`, or when EHM dropped into pass-through
mode at runtime, `SubscribeFromEvent` returns
`FAILED_PRECONDITION`. The legacy `WatchEvents`,
`WatchRoutes`, and `List*Events` surfaces are byte-identical
to pre-ADR-0072 behavior in all three cases — they're
backed by the existing in-memory rings.

**Producer set:** route, EVPN, session-lifecycle,
session-notification, policy, dataplane, and BFD. Dataplane
summary rollups and per-route FIB apply outcomes stay available
live through `WatchEvents`, and are also replayable through
`SubscribeFromEvent` when event history is enabled.

## Config Persistence

Neighbor mutations made through the gRPC API (`AddNeighbor`, `DeleteNeighbor`)
reserve config-persistence queue capacity before mutating runtime state, then
wait for the atomic config-file write (temp file + rename) to be acknowledged
after the peer manager accepts the change. Static-neighbor and dynamic-neighbor
runtime CRUD share the runtime-config coordinator lock with SIGHUP, so reload
sees either the pre-mutation TOML or the committed post-mutation TOML. If the
write is rejected after runtime apply, the accepted runtime mutation is rolled
back and the RPC reports failure.

There is no non-persisting mode. The daemon always takes a config path — the
positional argument, or `/etc/rustbgpd/config.toml` by default — so every
runtime mutation that persists writes to that file.

### The config file is rewritten in canonical form

Persistence serializes the daemon's whole runtime config snapshot and replaces
the file with it (temp file + rename). It is not a patch against your text, so
on the **first** runtime mutation the file you wrote is replaced by an
equivalent canonical rendering:

- **Comments are not preserved.** Every comment in the file is gone after the
  first persisted change.
- **Formatting and key order are not preserved.** Blank lines, spacing, table
  order, and inline-vs-expanded table style are all re-derived.
- **Defaults are canonicalized.** Most fields you left out appear with their
  default values (`dynamic_neighbors = []`, `evpn_instances = []`, and so on),
  so the file grows sections you never typed. Selected default-empty
  collections are omitted, including inline-policy `match_community`,
  `set_community_add`, and `set_community_remove`; omission and `[]` decode
  identically.
- **Ownership and mode change.** The rename installs a fresh file owned by the
  daemon user at mode `0600`, whatever the previous file's owner and mode were.

The rewritten file starts with a header saying the same thing, so a later
reader of the file is not surprised by it.

This is deliberate: a full canonical write is what makes the update atomic and
crash-safe, and what lets the daemon guarantee that a concurrent SIGHUP sees
either the pre-mutation file or the committed post-mutation file, never a torn
one. It is not going to change.

If you want an annotated config, keep the annotated copy under version control
and treat the daemon's file as generated output. Operators who never mutate at
runtime — file edits plus SIGHUP only — keep their comments, because SIGHUP
alone never writes the file.

### SIGHUP Reload

Sending `SIGHUP` to the rustbgpd process triggers a four-bucket config
reload, applied in dependency order:

1. **Definitions and hot-applied global flags** — neighbor sets, named
   policies, peer groups, global import / export chains,
   `honor_graceful_shutdown`, and control-plane-only
   `honor_blackhole`. Each bucket diffs against the running config and
   fires a single-shot command at the peer manager that goes through the
   same `apply_policy_change` / `apply_peer_group_change` paths the
   gRPC API uses. Hot-applied policy chains land at every affected
   peer's session task without tearing the BGP session.
2. **`[[neighbors]]` reconcile** — adds, deletes, and changes flow
   through `diff_neighbors()` + a single `ReconcilePeers` command with
   add/delete/change deltas.
3. **Deletes of obsolete definitions** in reverse-dependency order —
   so transient `still referenced` rejections don't fire while a
   peer group is being deleted before the chain that named it.
4. **Automatic Route Refresh on import-policy hot-apply** — when a
   peer's effective import chain changes,
   `PeerManager::update_runtime_policies` issues `soft_reset_in`
   (gated on Established) so routes already in `AdjRibIn` get
   re-evaluated. Operators do not need to follow up with a manual
   `softreset` after a chain swap.

Reload halts at the first step failure and returns a partial-state
snapshot, so the daemon's in-memory config tracks what the peer
manager actually applied (operator fixes the failing TOML and
reloads again to converge against the half-applied state). The
neighbor-reconcile step returns `None` on partial failure because
live state is genuinely ambiguous after a delete-then-readd partial;
earlier reload steps still land at the manager and remain in effect.

Inline `policy.import` / `policy.export` (the legacy global-fallback
statements), `[global]` ASN/router-id/families,
`[global.telemetry.grpc_*]` listener config, `[rpki]`, `[bmp]`,
`[mrt]`, and `apply_bum_enforcement` are
**restart-required** — they're surfaced under "Restart-required" in
`rustbgpd --diff` and logged at reload time with a one-line migration
hint to named definitions plus `import_chain` / `export_chain` where
applicable. EVPN tables (`[[evpn_instances]]`, `[[ethernet_segments]]`,
and `[[evpn_ip_vrfs]]`) are coordinator-gated instead: SIGHUP and the
whole-model `EvpnService.ApplyEvpnRuntime` RPC validate a full candidate,
converge the daemon actors in order, and advance the committed runtime
snapshot only after the actors accept the change. Supported live shapes include single L2VNI/IP-VRF/Ethernet-Segment
add/delete/redefine, additive build-up, atomic tenant teardown, `ip_vrf`
relink, and decomposable mixed edits ordered as deletes -> redefines ->
`ip_vrf` relinks -> adds. Unsupported dependency cycles, missing actors,
actor convergence failure, or restart-only IP-VRF identity changes pin back to
or fail-stop on the committed runtime model and keep the drift visible. The ADR-0061 `[[fib_tables]]` table is another
reload-applied surface: when the FIB reconciler is running it
**hot-applies** table edits on SIGHUP (see the `[[fib_tables]]` section),
advancing the snapshot only after the actor acks the new set; only *starting*
the FIB subsystem from an empty config still requires a restart. Runtime EVPN
mutation does not expose direct `AddEvpnInstance` / `DeleteEvpnInstance`
RPCs; unsupported shapes are tracked in
<https://github.com/lance0/rustbgpd/issues/268>.

Reload failures are reported per-step with structured logging
(bucket / target / error). The previous in-memory config snapshot
is preserved up to the point of failure.

---

## Validation rules

The following checks run at startup. Any failure prevents the daemon from
starting:

| Rule | Error |
|------|-------|
| Local `asn` must not be AS 0 | `invalid local ASN` |
| `router_id` must be a valid IPv4 dotted quad and must not be `0.0.0.0` | `invalid router_id` |
| Each `address` in `[[neighbors]]` must be a valid IP address (IPv4 or IPv6) | `invalid neighbor address` |
| IPv6 link-local `[[neighbors]]` must set `interface`; numbered neighbors must not | `invalid neighbor config` |
| `[[neighbors]]` identity must be unique by address for numbered peers and by `(address, interface)` for IPv6 link-local peers | `duplicate neighbor address/interface` |
| An IPv6 link-local address may not be bound to more than one interface in this release (the RIB keys peers by address; deferred per ADR-0069) | `not supported in this release` |
| `prometheus_addr` must be a valid `ip:port` | `invalid prometheus_addr` |
| `grpc_tcp.address` must be a valid `ip:port` when `grpc_tcp` is enabled | `invalid gRPC config` |
| `grpc_uds.path` must be absolute when configured | `invalid gRPC config` |
| `grpc_uds.mode` must be <= `0o777` | `invalid gRPC config` |
| `grpc_*.access_mode` must be `read_only` or `read_write` | `invalid gRPC config` |
| `grpc_*.max_tier` must be `read`, `sensitive_read`, `mutating`, or `operator_only` | TOML parse error |
| `grpc_*.token_file` must exist, be readable, and contain a non-empty token when configured | `invalid gRPC config` |
| `grpc_*.principal` must not be empty when configured | `invalid gRPC config` |
| `grpc_tcp.principal` requires `grpc_tcp.token_file` and is rejected on mTLS listeners because mTLS principals are derived from client certificates | `invalid gRPC config` |
| `security.grpc.enforcement = "tier"` requires every enabled listener to have mTLS, an explicit role-mapped principal, or an owner-only UDS mode (implicit `local-operator`); all problems are reported in one error with a paste-ready fix | `invalid gRPC config` |
| `[security.grpc.roles]` principal keys must not be empty and must not use the reserved `mtls-unresolved` / `local-operator` names; role values must be `observer`, `automation`, or `operator` | `invalid gRPC config` / TOML parse error |
| If `grpc_tcp`/`grpc_uds` tables are present, at least one listener must be enabled | `invalid gRPC config` |
| `hold_time` must be 0 (disabled) or >= 3 seconds | `invalid hold_time` |
| `min_hold_time` must be 3..=65535 and no greater than a non-zero effective `hold_time` | `invalid min_hold_time` |
| `send_hold_time` must be 0 (disabled) or greater than the effective `hold_time` (RFC 9687 §4.4) | `invalid send_hold_time` |
| `families` entries must be `"ipv4_unicast"`, `"ipv6_unicast"`, `"ipv4_flowspec"`, `"ipv6_flowspec"`, `"l2vpn_evpn"`, `"linkstate"`, `"linkstate_vpn"`, `"l3vpn_ipv4_unicast"`, `"l3vpn_ipv6_unicast"`, `"ipv4_labeled_unicast"`, `"ipv6_labeled_unicast"`, or `"rtc"` | `unknown address family` |
| `gr_restart_time` must be <= 4095 | `gr_restart_time exceeds 4095` |
| `gr_restart_time` must be > 0 when `graceful_restart` is enabled | `gr_restart_time must be > 0` |
| `gr_peer_restart_time_max` must be > 0 | `gr_peer_restart_time_max must be > 0` |
| `gr_peer_restart_time_max` must be <= 4095 | `gr_peer_restart_time_max <value> exceeds 4095 (12-bit max)` |
| `gr_stale_routes_time` must be > 0 and <= 3600 | `invalid gr_stale_routes_time` |
| Policy prefix length must not exceed AFI max (32 for IPv4, 128 for IPv6) | `invalid prefix length` |
| Policy entry must have at least one match condition (`prefix`, `match_community`, `match_as_path`, `match_as_path_length_ge`, `match_as_path_length_le`, `match_rpki_validation`, or `match_aspa_validation`) | `must have at least one match condition` |
| Import `match_rpki_validation`/`match_aspa_validation` evaluates against the current snapshot — routes arriving before the first VRP/ASPA table loads see `not_found`/`unknown`; later cache updates trigger inbound Route Refresh for established peers whose import policy depends on validation state | *(informational — no error)* |
| `match_as_path_length_ge` must not exceed `match_as_path_length_le` | `match_as_path_length_ge (...) exceeds match_as_path_length_le (...)` |
| `set_*` fields cannot be used with `action = "deny"` | `set_* fields cannot be used with action = "deny"` |
| `set_as_path_prepend.count` must be 1--10 | `count must be 1-10` |
| `match_as_path` must be a valid regex | `invalid regex` |
| RT/RO local administrator must be <= 65535 for a 4-octet ASN or dotted IPv4 administrator; numeric ASNs <= 65535 carry a u32 local value | `local admin ... exceeds 65535 for ...` |
| RPKI `refresh_interval`, `retry_interval`, `expire_interval` must be > 0 | `must be > 0` |
| RPKI `expire_interval` must be >= `refresh_interval` | `expire_interval must be >= refresh_interval` |
| RPKI cache addresses must be unique numeric `IP:port` endpoints (bracketed for IPv6) | `invalid address` / `duplicate address` |
| Named policy referenced in chain must exist in `[policy.definitions]` | `undefined policy` |
| Inline policy and policy chain cannot both be set for the same neighbor/direction | `mutually exclusive` |
| `route_server_client` is only valid on eBGP neighbors | `invalid route_server_client` |
| `per_client_best` requires `route_server_client = true` | `invalid route_server_client` |
| `disable_ipv4_unicast = true` requires at least one non-`ipv4_unicast` effective family | `invalid neighbor config` |
| `role` is only valid on eBGP neighbors; `strict_role = true` requires `role` | `invalid neighbor config` |
| `remove_private_as` must be `"remove"`, `"all"`, or `"replace"` (eBGP only) | `invalid remove_private_as` |
| MRT `output_dir` must not be empty | `output_dir must not be empty` |
| MRT `dump_interval` must be > 0 | `dump_interval must be > 0` |
| BMP collector `address` must be a valid `ip:port` | `invalid BMP collector address` |
| BMP collector `reconnect_interval` must be > 0 | `reconnect_interval must be > 0` |
| `cluster_id` must be a valid IPv4 address | `invalid cluster_id` |
| `runtime_state_dir` must not be empty | `runtime_state_dir must not be empty` |
| `[[fib_tables]].name` must be unique and match the identifier rule | `duplicate fib table name` / `invalid fib table name` |
| `[[fib_tables]].table_id` must be unique and must not be `0`, `252`, `253`, `254`, or `255` | `duplicate fib table_id` / `reserved fib table_id` |
| `[[fib_tables]].families` must be non-empty, contain no duplicates, and contain only `ipv4_unicast` / `ipv6_unicast` | `fib table families must not be empty` / `duplicate fib table family` / `unsupported fib table family` |
| `[[fib_tables]].allowed_peer_groups` entries must reference existing peer groups and contain no duplicates | `undefined peer_group` / `duplicate allowed_peer_groups` |
| `[[fib_tables]].allowed_neighbors` entries must parse as IP addresses and contain no duplicates | `invalid allowed_neighbors` / `duplicate allowed_neighbors` |
| `[[fib_tables]].max_routes` must be omitted or greater than zero | `max_routes must be greater than zero` |
| `llgr_stale_time` must be <= 16777215 (24-bit) | `llgr_stale_time exceeds maximum` |
| `route_reflector_client` requires iBGP (local ASN == remote ASN) | `route_reflector_client requires iBGP` |
| `local_ipv6_nexthop` must be a valid non-link-local, non-loopback, non-multicast IPv6 address | `invalid local_ipv6_nexthop` |
| `ge` must be >= prefix length and <= AFI max (32 for IPv4, 128 for IPv6) | `invalid ge` |
| `le` must be <= AFI max | `invalid le` |
| `ge` must be <= `le` when both are set | `ge must be <= le` |
| Config file must be valid TOML | `failed to parse TOML` |

### Defaults applied at runtime

| Field | Default value |
|-------|---------------|
| `hold_time` | 90 seconds |
| `min_hold_time` | unset (RFC 4271 compatibility: accept 0 or >= 3) |
| `send_hold_time` | `max(480, 2 × hold_time)` seconds (RFC 9687 §6) |
| `connect_retry_secs` | 5 seconds (not configurable) |
| gRPC listener | UDS at `<runtime_state_dir>/grpc.sock` with mode `0o600` |
| `ttl_security` | `false` |
| `families` | `["ipv4_unicast"]` for IPv4 peers; `["ipv4_unicast", "ipv6_unicast"]` for IPv6 peers |
| `graceful_restart` | `true` |
| `gr_peer_restart_time_max` | 4095 seconds (full peer-advertised RFC 4724 range) |
| `gr_restart_time` | 120 seconds |
| `gr_stale_routes_time` | 360 seconds |
| `llgr_stale_time` | 0 (disabled) |
| `description` | peer address used as label |
| `route_server_client` | `false` |
| `per_client_best` | `false` |
| `prefix_orf_receive` | `false` |
| `disable_ipv4_unicast` | `false` |
| `role` / `strict_role` | disabled / `false` |
| `remove_private_as` | disabled (absent) |
| Policy default action | permit (when no entry matches) |
