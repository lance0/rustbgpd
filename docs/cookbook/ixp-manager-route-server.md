# IXP Manager route server: Foil export → render → activate → lifecycle

**When this is you:** your exchange runs IXP Manager v7.4 as the member and
router database, and you want a rustbgpd route server that IXP Manager
provisions the way it provisions your BIRD route servers — members, IRR
sets, max-prefix, MD5, RPKI, and route-server UI filters come from the
member DB; nothing is hand-written per member; IXP Manager's router
lock/update lifecycle drives every reconfiguration; members see the
route server through IXP Manager's looking glass.

This is one of three IXP provisioning modes
([the fork](README.md#ixp-provisioning-three-modes)). If you have no
external provisioning source, start from the hand-written
[route-server recipe](route-server.md); if your member data lives in
arouteserver's `general.yml`/`clients.yml`, use the
[IXP filter pipeline](ixp-filter-pipeline.md). The modes are mutually
exclusive per route server: the renderer owns the whole output directory
in both automated modes, and this one activates only unmodified, receipted
candidates.

**Proven by:** M96 (pinned v7.4 Foil render → atomic local activation:
initial, no-op, hot reload, and pre-effect restoration against
MD5-authenticated FRR) and M97 (authenticated lock/fetch/callback lifecycle
for two IPv4/IPv6 handles on one host, shared fence, MD5-FRR session
continuity) — both local gates, described in
[`INTEROP.md`](../INTEROP.md#ixp-manager-v74-manual-configuration-oracle);
and the pinned IXP Manager / Bird's Eye contract oracle
([`tests/compat/ixp-manager-birdseye/`](../../tests/compat/ixp-manager-birdseye/README.md)),
which runs the real IXP Manager v7.4.0 router-config generator, PHP
looking-glass consumer, and MySQL fixture against the real renderer,
checker, daemon, and adapter. Every "expected output" block below is a
real invocation of the release binaries on the checked-in v7.4 capture.

The pipeline:

```text
IXP Manager v7.4 member DB
        │  Foil template (json.foil.php in your VIEW_SKIN)
        ▼
router-config/v2 JSON                      fetched over HTTPS, mode 0600
        │  rs-config-render --input-format ixp-manager-v2 --check-with rustbgpd
        ▼
candidate/: config.toml + policy/*.rpol + birdwatcher-protocol-aliases.conf
            + render-receipt.json          (written last, after --check --strict)
        │  rs-config-render activate       (immutable generation, atomic `current` swap,
        ▼                                   one synchronous reload, rbgp settle)
rustbgpd@<handle>.service reads <runtime>/activation/current/config.toml
        │
        ▼
birdwatcher-adapter --protocol-alias-file …/current/birdwatcher-protocol-aliases.conf
        │
        ▼
IXP Manager looking glass (pinned Bird's Eye journeys)
```

`ixp-manager-lifecycle run` wraps the middle of that diagram — lock, fetch,
render, check, activate, callback — in one command (section 4). The manual
steps in sections 2–3 are the same code path and the right place to start.

## 1. The Foil template skin

The exporter is original GPL-2.0-only source kept outside every binary,
package, archive, and image:
[`integrations/ixp-manager/gpl-2.0-only/`](../../integrations/ixp-manager/gpl-2.0-only/README.md).
Install `api/v4/router/server/rustbgpd/json.foil.php` beneath the same path
in your active IXP Manager skin, then set the router's template to
`api/v4/router/server/rustbgpd/json`:

```text
resources/skins/<VIEW_SKIN>/api/v4/router/server/rustbgpd/json.foil.php
```

IXP Manager then renders the strict `rustbgpd.ixp-manager.router-config/v2`
JSON document through its normal router configuration generator. The
template reads IXP Manager's sanitized session, IRR, max-prefix,
authentication, RPKI, and route-filter state; it copies no BIRD template.
It also *reports* things the renderer must refuse rather than silently
drop — active BIRD skin overrides, the legacy implicit no-transit token —
and resolves the pinned 15-ASN default no-transit list (or your explicit
`IXP_NO_TRANSIT_ASNS_OVERRIDE`) so old/new version skew fails closed.

One router in IXP Manager = one **handle** = one rustbgpd instance. A
dual-stack route server is two handles (`rs1-ipv4`, `rs1-ipv6`) on one
host — section 5.

## 2. Fetch and render a candidate

Fetch the document with authenticated `curl` into a regular, non-symlink,
mode-0600 file owned by the `rustbgpd` service identity; the renderer has
no HTTP client and never sees the API key in this mode:

```console
umask 077
sudo -u rustbgpd curl --fail --silent --show-error \
  -H "X-IXP-Manager-API-Key: $(cat /var/lib/rustbgpd/ixp-manager/api-key)" \
  -o /var/lib/rustbgpd/ixp-manager/router.json \
  https://ixp.example.net/admin/api/v4/router/gen-config/rs1-ipv4
```

Render into an absent (or empty, mode-0700) candidate directory. IXP
Manager mode runs the selected binary as `rustbgpd --version` and then
`rustbgpd --check --strict <candidate>/config.toml` itself, with child
output suppressed so authentication values cannot leak through
diagnostics, and writes `render-receipt.json` last — only after the strict
check passes:

```console
sudo -u rustbgpd /usr/bin/rs-config-render \
  --input-format ixp-manager-v2 \
  --context /var/lib/rustbgpd/ixp-manager/router.json \
  --out-dir /var/lib/rustbgpd/ixp-manager/candidate \
  --router-handle rs1-ipv4 \
  --runtime-state-dir /var/lib/rustbgpd/rs1-ipv4 \
  --max-prefix-restart-seconds 300 \
  --check-with /usr/bin/rustbgpd
```

Expected output (the checked-in v7.4 capture has two members, handle
`b2-rs1-lan1-ipv4`):

```console
$ rs-config-render --input-format ixp-manager-v2 --context router.json \
    --out-dir candidate --router-handle b2-rs1-lan1-ipv4 \
    --runtime-state-dir /var/lib/rustbgpd/b2-rs1-lan1-ipv4 \
    --max-prefix-restart-seconds 300 --check-with /usr/bin/rustbgpd
validated 5 candidate file(s) + receipt into candidate
$ echo $?
0
$ ls -la candidate candidate/policy
candidate:
-rw-------  birdwatcher-protocol-aliases.conf
-rw-------  config.toml
drwx------  policy
-rw-------  render-receipt.json
candidate/policy:
-rw-------  client-1.rpol
-rw-------  client-4.rpol
-rw-------  ixp-hygiene.rpol
$ cat candidate/birdwatcher-protocol-aliases.conf
pb_0001_as1213=10.1.0.10@master4
pb_0004_as112=10.1.0.6@master4
```

The receipt is the deploy gate — a candidate without one is incomplete and
must not be activated:

```json
{
  "counts": { "clients": 2, "origins": 2, "prefixes": 2 },
  "generated_files": {
    "birdwatcher-protocol-aliases.conf": "08250f41…",
    "config.toml": "5d7d0eb0…",
    "policy/client-1.rpol": "3cf619c8…",
    "policy/client-4.rpol": "1666481b…",
    "policy/ixp-hygiene.rpol": "326b2121…"
  },
  "host": { "router_handle": "b2-rs1-lan1-ipv4",
            "runtime_state_dir": "/var/lib/rustbgpd/b2-rs1-lan1-ipv4" },
  "input": { "ixp_manager_version": "7.4.0", "router_handle": "b2-rs1-lan1-ipv4",
             "schema": "rustbgpd.ixp-manager.router-config/v2", "sha256": "072f1678…" },
  "refusals": { "active_ui_filters": 0, "multi_address_clients": 0,
                "route_server_skin_files": 0, "status": "passed" },
  "strict_check": { "binary_version": "rustbgpd 0.65.0", "passed": true }
}
```

### What the candidate looks like

You do not write this file; read it once so the shape is familiar. This is
the exact `config.toml` rendered from the checked-in capture (MD5 values
replaced; the file as shown passes `rustbgpd --check --strict`):

```toml
# GENERATED candidate from IXP Manager 7.4.0.
[global]
asn = 65501
router_id = "192.0.2.18"
runtime_state_dir = "/var/lib/rustbgpd/b2-rs1-lan1-ipv4"
listen_port = 179
listen_addresses = ["192.0.2.18"]
ebgp_requires_policy = true

[global.telemetry]
log_format = "json"

[global.telemetry.grpc_uds]
path = "/var/lib/rustbgpd/b2-rs1-lan1-ipv4/grpc.sock"
mode = 0o600

[rpki]
[[rpki.cache_servers]]
address = "127.0.0.1:3323"

[policy.definitions.ixp-transparent-export]
default_action = "permit"

[policy]
rpol_files = [
    "policy/ixp-hygiene.rpol",
    "policy/client-1.rpol",
    "policy/client-4.rpol",
]
export_chain = ["ixp-transparent-export", "ixp-manager-own-as-export-scrub"]

[[neighbors]]
address = "10.1.0.10"
remote_asn = 1213
description = "HEAnet"
families = ["ipv4_unicast"]
route_server_client = true
role = "route_server"
next_hop_ownership = "strict_peer"
per_client_best = true
rs_control_communities = true
interpret_rfc1997 = true
max_prefixes_ipv4 = 900
max_prefix_restart_seconds = 300
import_policy_chain = ["reject-special-purpose", "ixp-hygiene", "ixp-manager-hygiene", "client-1"]
export_policy_chain = ["ixp-transparent-export", "client-1-receive", "ixp-manager-own-as-export-scrub"]
md5_password = "member-md5-from-ixp-manager"

[[neighbors]]
address = "10.1.0.6"
remote_asn = 112
description = "AS112"
families = ["ipv4_unicast"]
route_server_client = true
role = "route_server"
next_hop_ownership = "strict_peer"
per_client_best = true
rs_control_communities = true
interpret_rfc1997 = true
max_prefixes_ipv4 = 20
max_prefix_restart_seconds = 300
import_policy_chain = ["reject-special-purpose", "ixp-hygiene", "ixp-manager-hygiene", "client-4"]
md5_password = "member-md5-from-ixp-manager"
```

Things to notice, because they are the route-server shapes the other
recipes explain: every member is a transparent `route_server_client` with
the RFC 9234 `route_server` role, strict next-hop ownership (RFC 7948
§4.8), `per_client_best` path-hiding mitigation, IXP Manager's control
communities, and `interpret_rfc1997` set from the router's IXP Manager
`rfc1997_passthru` flag (off in this capture, so the server enforces
`NO_EXPORT` itself; the hand-written example derives passthrough). The
import chain is hygiene → IXP Manager hygiene → the member's IRR set; every
export chain ends with `ixp-manager-own-as-export-scrub`, which removes
large communities under the router ASN and preserves everyone else's.
`ebgp_requires_policy = true` makes deleting a chain fail closed. The
gRPC socket and `runtime_state_dir` are fixed under the handle's directory;
the candidate is mode 0600 because it carries the members' MD5 secrets.

The render refuses (exit 2, no receipt) rather than degrade: active BIRD
skin overrides, applicable UI filters it cannot translate exactly, the
legacy implicit no-transit token, quarantine or non-route-server routers,
IRR-disabled or empty clients, missing or zero-port RPKI caches,
wrong-family or multi-address clients, unknown schema fields, placeholder
or overlong MD5, and symlink or public input/output paths. Each refusal
names its cause on stderr; the member data is the thing to fix.

## 3. Activate atomically

Pre-create the per-handle state once, and enable the packaged per-handle
unit ([`rustbgpd@.service`](../../examples/systemd/rustbgpd@.service) —
`%i` is the literal handle; it reads
`/var/lib/rustbgpd/%i/activation/current/config.toml` with a private
runtime/UDS and no write access to the shared fence):

```sh
handle=rs1-ipv4
sudo install -d -m 0700 -o rustbgpd -g rustbgpd \
  "/var/lib/rustbgpd/$handle" "/var/lib/rustbgpd/$handle/activation" \
  /var/lib/rustbgpd/ixp-manager-host
sudo systemctl enable "rustbgpd@$handle"
```

Authorize the `rustbgpd` account in sudoers for exactly
`/usr/bin/systemctl reload-or-restart rustbgpd@rs1-ipv4` — the literal
instance, never a wildcard. Then activate the reviewed candidate with an
exact executable and literal arguments (nothing is shell-evaluated):

```console
sudo -u rustbgpd /usr/bin/rs-config-render activate \
  --router-handle rs1-ipv4 \
  --candidate /var/lib/rustbgpd/ixp-manager/candidate \
  --runtime-state-dir /var/lib/rustbgpd/rs1-ipv4 \
  --state-dir /var/lib/rustbgpd/rs1-ipv4/activation \
  --host-state-dir /var/lib/rustbgpd/ixp-manager-host \
  --check-with /usr/bin/rustbgpd --rbgp /usr/bin/rbgp \
  --rbgp-addr unix:///var/lib/rustbgpd/rs1-ipv4/grpc.sock \
  --activation-command /usr/bin/sudo \
  --activation-arg=-n --activation-arg /usr/bin/systemctl \
  --activation-arg reload-or-restart --activation-arg rustbgpd@rs1-ipv4
```

Add `--initial` only for the very first publication, when no `current`
generation and no reachable daemon exist. The helper rechecks the candidate
against its receipt, copies it into an immutable content-addressed
generation, atomically renames the relative `current` symlink, runs the one
synchronous activation command, and requires both `rbgp health` and
`rbgp config diff` against the live daemon to settle. Equal content is a
no-op.

Expected output — initial activation, the settled state, and a second run
of the same candidate:

```console
$ rs-config-render activate … --candidate candidate-1 --initial
activation activated
$ echo $?
0
$ rbgp -s unix:///var/lib/rustbgpd/b2-rs1-lan1-ipv4/grpc.sock neighbor
Neighbor  AS   State  Uptime   Rx Pfx Tx Pfx  Description
10.1.0.6  112  Active 00:00:00      0      0  AS112
10.1.0.10 1213 Active 00:00:00      0      0  HEAnet
$ ls -la /var/lib/rustbgpd/b2-rs1-lan1-ipv4/activation
-rw-------  activation-receipt.json
-rw-------  activation.lock
lrwxrwxrwx  current -> generations/a43f75ab…
drwx------  generations
$ rs-config-render activate … --candidate candidate-1
activation noop
```

The private `activation-receipt.json` (written last) records what was
proven:

```json
{
  "activation_runs": 1,
  "candidate_sha256": "a43f75ab…",
  "host": { "router_handle": "b2-rs1-lan1-ipv4",
            "runtime_state_dir": "/var/lib/rustbgpd/b2-rs1-lan1-ipv4",
            "activation_state_dir": "/var/lib/rustbgpd/b2-rs1-lan1-ipv4/activation",
            "host_state_dir": "/var/lib/rustbgpd/ixp-manager-host",
            "rbgp_addr": "unix:///var/lib/rustbgpd/b2-rs1-lan1-ipv4/grpc.sock" },
  "initial": true,
  "phases": {
    "candidate_activation_ran": true,
    "candidate_link": { "durable": true, "published": true },
    "health_checked": true,
    "initial_unreachable_checked": true,
    "rollback_activation_ran": false,
    "rollback_link": { "durable": false, "published": false },
    "runtime_equal": true
  },
  "previous_generation": null,
  "schema": "rustbgpd.ixp-manager.activation/v1",
  "status": "activated",
  "strict_check": { "binary_version": "rustbgpd 0.65.0", "passed": true }
}
```

A later member change is a fresh fetch, a fresh render into a fresh
candidate directory, and another `activate`: the daemon hot-reloads
(parse-then-swap SIGHUP through `reload-or-restart`), `current` moves to
the new generation, and the previous generation stays on disk. Re-rendering
the same upstream state produces byte-identical files and a no-op.

Exit codes, and exactly what each one guarantees:

| Exit | Meaning | State afterwards |
|---|---|---|
| 0 | activated, or no-op (equal content) | `current` → the candidate's generation; receipt current |
| 2 | refused before any effect (bad candidate/receipt, wrong modes, `--initial` misuse, helper contract violation) | unchanged |
| 4 | the activation command **could not start** | the prior `current` is restored without a second activation and the prior runtime is verified unchanged — proven pre-effect restoration |
| 5 | the command started and then failed, timed out, or the runtime did not settle | `current` stays on the candidate; **recovery is operator-owned**; a synced owner fence stays in the host-state directory and every later activation or lifecycle run returns 5 until it is resolved — [Activation manual recovery](activation-manual-recovery.md) |

Real exit-4 and exit-5 runs, on a changed candidate:

```console
$ rs-config-render activate … --candidate candidate-2 --activation-command /usr/local/bin/does-not-exist
rs-config-render: activation: activation command did not start; prior generation restored
$ echo $?
4
$ readlink /var/lib/rustbgpd/b2-rs1-lan1-ipv4/activation/current
generations/a43f75ab…                       # unchanged

$ rs-config-render activate … --candidate candidate-3 --activation-command /bin/false
rs-config-render: activation: recovery required; inspect private activation state
$ echo $?
5
$ ls /var/lib/rustbgpd/ixp-manager-host
ixp-manager-host-fence.json  ixp-manager-host.lock
$ rs-config-render activate … --candidate candidate-2      # anything, while the fence exists
rs-config-render: activation: recovery required; inspect private activation state
$ echo $?
5
$ rbgp -s unix:///var/lib/rustbgpd/b2-rs1-lan1-ipv4/grpc.sock health
Status:  healthy                            # the daemon itself is untouched
```

## 4. Let IXP Manager drive it

`ixp-manager-lifecycle run` is the same renderer and the same activation
helper wrapped in IXP Manager v7.4's router API: acquire the router update
lock, fetch the Foil JSON over HTTPS, render and strictly check a fresh
private candidate, activate it, then deliver `updated` (or
`release-update-lock` on a definite pre-activation refusal). This is what a
cron entry or IXP Manager's own "update router" flow should call:

```console
sudo -u rustbgpd /usr/bin/rs-config-render ixp-manager-lifecycle run \
  --ixp-origin https://ixp.example.net \
  --router-handle rs1-ipv4 \
  --api-key-file /var/lib/rustbgpd/ixp-manager/api-key \
  --candidate-dir /var/lib/rustbgpd/ixp-manager/candidate-1 \
  --runtime-state-dir /var/lib/rustbgpd/rs1-ipv4 \
  --state-dir /var/lib/rustbgpd/rs1-ipv4/activation \
  --host-state-dir /var/lib/rustbgpd/ixp-manager-host \
  --max-prefix-restart-seconds 300 \
  --check-with /usr/bin/rustbgpd --rbgp /usr/bin/rbgp \
  --rbgp-addr unix:///var/lib/rustbgpd/rs1-ipv4/grpc.sock \
  --activation-command /usr/bin/sudo \
  --activation-arg=-n --activation-arg /usr/bin/systemctl \
  --activation-arg reload-or-restart --activation-arg rustbgpd@rs1-ipv4
```

Rules that are enforced, not advisory: a new absent-or-empty mode-0700
`--candidate-dir` per run; the API key in an absolute, regular, mode-0600
file (never argv or environment; it appears only in the
`X-IXP-Manager-API-Key` header and is never journaled); HTTPS with platform
roots, redirects and proxies disabled, bounded deadlines and body sizes.
Lifecycle intent is written and synced before every upstream request. On
success the command prints `IXP Manager lifecycle updated`.

| Exit | Meaning |
|---|---|
| 0 | `updated` delivered |
| 2 | no lock acquired, or a definite pre-activation refusal was released back to IXP Manager |
| 4 | activation command never started; exact prior runtime proven; release delivered |
| 5 | lock acquisition or activation effect is **uncertain** — no callback is issued; the owner fence stands; operator recovery ([runbook](activation-manual-recovery.md)) |
| 6 | one durable `updated` or release callback is still pending — retry only that with `resume` |

```console
sudo -u rustbgpd /usr/bin/rs-config-render ixp-manager-lifecycle resume \
  --ixp-origin https://ixp.example.net --router-handle rs1-ipv4 \
  --api-key-file /var/lib/rustbgpd/ixp-manager/api-key \
  --runtime-state-dir /var/lib/rustbgpd/rs1-ipv4 \
  --state-dir /var/lib/rustbgpd/rs1-ipv4/activation \
  --host-state-dir /var/lib/rustbgpd/ixp-manager-host \
  --rbgp-addr unix:///var/lib/rustbgpd/rs1-ipv4/grpc.sock
```

`resume` never refetches, rerenders, or activates; it replays the pending
callback with the exact same handle/runtime/activation/host-state/UDS
identity. Delivery is at-least-once (IXP Manager v7.4 offers no
idempotency token). `resume` has no automatic action for exit 5.

## 5. Paired handles on one host

A second handle — the IPv6 side of the same route server, or a second
route server a small exchange co-hosts — is a second IXP Manager router
entry, a second `rustbgpd@<handle>` instance, and its own
runtime/activation/UDS directories, all under the same `rustbgpd` account
and the **same** `--host-state-dir`. The shared host-state directory is
what serializes lifecycle ownership across the host (M97: two handles,
distinct PIDs, TCP/179 listeners, state, sessions, and failure domains;
one fence; paired competing-lock behavior; sequential callbacks):

```sh
for handle in rs1-ipv4 rs1-ipv6; do
  sudo install -d -m 0700 -o rustbgpd -g rustbgpd \
    "/var/lib/rustbgpd/$handle" "/var/lib/rustbgpd/$handle/activation"
  sudo systemctl enable "rustbgpd@$handle"
done
sudo install -d -m 0700 -o rustbgpd -g rustbgpd /var/lib/rustbgpd/ixp-manager-host
```

Each handle gets its own sudoers line and its own lifecycle invocation;
run them one at a time, and note that a fence left by either handle makes
every run on the host return 5 until it is resolved. The second *host* of
a redundant pair is a second, independent lifecycle with its own router
handle in IXP Manager and its own host-state directory — there is no
cross-host coordination, and none is needed: the
[paired route servers](paired-route-servers.md) runbook's staggered
rollout and `rbgp diff advertised` consistency check apply unchanged.

## 6. Observe through the Birdwatcher surface

Every candidate carries `birdwatcher-protocol-aliases.conf`, IXP Manager's
`pb_<vlan-interface-id>_as<asn>` protocol names bound to the member's
session address and `master4`/`master6` table, mode 0600, hashed into the
receipt and published atomically with the daemon generation at
`<runtime-state-dir>/activation/current/birdwatcher-protocol-aliases.conf`.
Point the [birdwatcher adapter](../../examples/birdwatcher-adapter/README.md)
at that stable path and send it `SIGHUP` after every successful activation
(neither the renderer nor the helper signals it — that is your one
post-activation step, and the file-backed resolver reloads as one whole
generation without changing the adapter PID; a malformed file is rejected
and the prior generation stays):

```sh
birdwatcher-adapter \
  --grpc-addr unix:///var/lib/rustbgpd/rs1-ipv4/grpc.sock \
  --listen 127.0.0.1:8080 \
  --protocol-alias-file /var/lib/rustbgpd/rs1-ipv4/activation/current/birdwatcher-protocol-aliases.conf
```

Expected shape of the IXP Manager inventory journey, against the activated
capture (trimmed):

```console
$ curl -s http://127.0.0.1:8080/protocols/bgp
{"api":{"Version":"rustbgpd 0.65.0","version":"rustbgpd 0.65.0",…},
 "protocols":{
  "pb_0001_as1213":{"bgp_state":"Active","description":"HEAnet","neighbor_address":"10.1.0.10",
                    "neighbor_as":1213,"protocol":"pb_0001_as1213","routes":{"exported":0,"filtered":0,"imported":0},
                    "table":"master4",…},
  "pb_0004_as112":{…,"neighbor_address":"10.1.0.6","neighbor_as":112,"table":"master4",…}}}
```

Point IXP Manager's looking glass at the adapter as it would be pointed at
Bird's Eye. What it gets is the pinned set of v7.4 journeys (the exact
list is the boundary, below): router status, live BGP inventory and
per-protocol detail, symbols, a member's received and exported routes
including exact-prefix lookups, a bounded longest-prefix table search, an
atomic capped full-table view, and the member filtered-prefix view — the
"why was my prefix filtered" page — which the adapter answers from the
daemon's retained rejected routes, one synthesized `<router ASN>:1101:<id>`
reason per route after scrubbing any wire-supplied value in that
namespace. For the member-support flow from the operator side
(`rbgp rib received <member> --rejected`, `rbgp policy explain`), see the
[route-server recipe](route-server.md#member-support-the-filtered-route-view).

## Watch

The [route-server watch table](route-server.md#watch) applies unchanged.
Add, for this mode:

| Signal | Healthy shape |
|--------|---------------|
| age of the newest `render-receipt.json` / `activation-receipt.json` | within your refresh cadence — a stale pair means the lifecycle is not running or is refusing; alert on age, not on absence |
| `bgp_policy_generation_loaded_timestamp_seconds` | moves on every activation that changed policy; flat across a member change means the candidate was a no-op or never activated |
| `readlink <runtime>/activation/current` vs the latest candidate receipt's `candidate_sha256` | equal after every exit-0 run |
| `<host-state-dir>/ixp-manager-host-fence.json` | absent — its presence is an exit-5 condition waiting for an operator |
| `bgp_session_state_transitions_total` | flat across activations — hot reloads must not bounce members |
| `bgp_rejected_routes_retained{peer}` | the member filtered-prefix view reads from this store; a member whose count keeps climbing is a member-support conversation |

## Failure modes

**Render exits 2 and names a refusal.** The member data or the skin is the
problem, not the daemon: an active BIRD skin override (the exporter lists
`route_server_skin_files`), a UI filter the bounded subset cannot express,
a client with IRR disabled or an empty IRR answer, a zero-port RPKI cache,
multiple addresses on one client. Fix it in IXP Manager; nothing was
published and no receipt was written — the receipt exists only after a
strict pass.

**Activate exits 2.** The candidate is not the renderer's (hand-edited
files fail the receipt hash recheck — "immutable generation content
mismatch"), a state path is wrong (the runtime basename must equal the
handle; the activation path must be exactly `<runtime>/activation`; mode
0700, owned by `rustbgpd`), or `--initial` was passed with a live daemon
or omitted on first publication. Nothing was published.

**Activate exits 4.** `sudo`/`systemctl` could not be executed (sudoers
line missing, wrong path). The prior generation is restored and the prior
runtime proven unchanged. Fix the command and re-run.

**Activate or lifecycle exits 5.** The command started and something after
it is unproven: a rejected reload, a daemon that did not settle within
`--settle-seconds`, a timeout, or a lifecycle lock state that is uncertain.
Nothing is retried for you, and every later run returns 5 while the fence
stands. Confirm the candidate's health with `rbgp health` and
`rbgp neighbor`, decide keep-or-roll-back, release the fence, handle the
receipt, then resume automation — the ordered checklist is
[Activation manual recovery](activation-manual-recovery.md).

**Lifecycle exits 6.** The router was activated (or released) but the
callback to IXP Manager is pending: run `resume` with the same identity.
Until it succeeds, IXP Manager still shows the router locked.

**A member's routes never appear; the session is Established.** Same as
every route server: `rbgp rib received <member> --rejected` lists the
retained rejections with the deciding term; the IXP Manager filtered-prefix
view shows the same rows to the member, tagged `<ASN>:1101:<id>`.

**Members cannot establish after a reload.** Check MD5: the candidate
carries IXP Manager's per-session password verbatim; a member whose IXP
Manager record has a placeholder or overlong password is refused at render,
not silently rendered without authentication.

**The route server is missing from the generated Nagios configuration, and
nothing complained.** If the router row in IXP Manager was added without
API type `Birdseye` and the Birdwatcher adapter URL, both of IXP Manager's
Nagios configuration generators return HTTP 200 and silently omit the
router — an unmonitored route server with no error anywhere
([M98](../INTEROP.md), against pinned v7.4.0). Fix: set the router row's
API type to `Birdseye` and its API URL to the adapter. Check: the generated
Nagios configuration must contain the router's host entry.

**The looking glass shows `bgp_<address>` names instead of `pb_…`.** The
adapter was not pointed at the published alias file, or was not SIGHUPed
after activation. Point it at the `current` path (not a generation path)
and send `SIGHUP`; unchanged content is a no-op.

## The boundary

Stated plainly, verified against the pinned contract
([`contract.json`](../../tests/compat/ixp-manager-birdseye/contract.json))
and the adapter at this commit:

- **`runtime_compatibility` is `false`.** The adapter serves exactly the
  pinned IXP Manager v7.4 journeys listed in section 6 (`runtime_supported`
  in the contract: exact protocol/export route, filtered-prefix wildcard,
  less-specific longest-prefix match, atomic full-table and all-candidate
  snapshots, file-backed alias reconfiguration, active reject-reason
  inventory, live session transport detail). `api.version` is rustbgpd
  product identity, not a Bird's Eye version claim. Full-table *counts*,
  other large-community wildcard queries, live hold/keepalive countdowns,
  and the complete IXP Manager UI-filter policy engine are unsupported;
  any Bird's Eye client other than the pinned IXP Manager consumer, and
  Alice-LG beyond the separately documented
  [Birdwatcher subset](ixp-filter-pipeline.md#6-looking-glass-alice-lg-via-the-birdwatcher-adapter),
  is outside what is proven.
- **The reject-reason vocabulary is complete for the pinned templates.**
  The ten reasons the v7.4 route-server templates actually emit —
  `1,3,5,6,7,8,9,10,13,14` (prefix length, bogon, AS-path length/first-AS,
  NEXT_HOP, IRRDB prefix/origin, RPKI-invalid, transit-free AS) — are
  runtime-supported and the member filtered-prefix page renders them. The
  five IXP Manager defines but its templates never set (`2,4,11,12,15`)
  and every ambiguous or custom cause fall back to `0`
  ("Route was filtered"). The pinned PHP consumer translates all fifteen
  display strings; emission of the defined-only five is unsupported.
- **Protocol aliases reload.** File-backed aliases
  (`--protocol-alias-file`) reload as one whole resolver generation on
  `SIGHUP`; the activation publishes the new file atomically with the
  daemon generation. Direct `--protocol-alias` values remain startup-only.
  Nothing signals the adapter automatically.
- **The bounded UI-filter subset.** Advertise actions and ordered receive
  AS_IS/deny/PREPEND, including reachable overlap compiled into at most
  4096 disjoint cells, 256 rows per client, 4096 total; 255 prepends
  succeed, 256 refuse. This is not a generic IXP Manager policy engine and
  not a custom-skin translator.
- **Local host only.** Render, activation, and lifecycle act on the local
  host: local state directories, a local executable as the activation
  command, one fence per host. A redundant pair on two hosts is two
  independent lifecycles. There is no remote activation and no cross-host
  fence.
- **Generations are retained, never pruned.** Every activated generation
  stays under `<runtime>/activation/generations/<sha256>` for inspection;
  the helper does not prune, retry indefinitely, deploy services, or call
  IXP Manager from `activate`. Disk growth is yours to manage.
- **Single-session clients, IPv4/IPv6 unicast, route-server routers only.**
  Multi-address clients, quarantine and non-route-server modes, and
  protocols other than 4/6 are refused at render. Filter translation
  beyond the bounded subset, custom-skin migration, and multi-address
  parity remain open.
- **No shadow/receive-only posture from this path.** IXP Manager mode
  refuses the site-local overlays (`--extra-rpol`/`--merge-toml`) and the
  helper activates only unmodified receipted candidates, so a deny-all
  export route server cannot be produced here — see the
  [shadow pilot](route-server-shadow-pilot.md) for what an IXP Manager
  site does instead.

Everything above the line is proven by M96/M97 and the contract oracle on
the pinned v7.4.0 commit. What does not exist yet is long-running history:
the lifecycle stack has days of use behind it, where the route-server
daemon itself has the [24 h flagship soak](../soaks/soak-rs-flagship-24h.md)
and the [IXP receipt matrix](../perf/ixp-matrix-2026-07.md). Both facts
belong in your evaluation.

## See also

- [IXP route server](route-server.md) — the hand-written mode and the
  route-server semantics every mode shares (transparency, roles, RPKI,
  path-hiding, member support).
- [IXP filter pipeline](ixp-filter-pipeline.md) — the arouteserver-driven
  mode (`general.yml`/`clients.yml` → `rs-config-render` → reload).
- [Route-server shadow pilot](route-server-shadow-pilot.md) — a
  zero-blast-radius pilot beside your incumbent, per mode.
- [Paired route servers](paired-route-servers.md) — two instances,
  staggered rollout, `rbgp diff advertised`.
- [`tools/rs-config-render/README.md`](../../tools/rs-config-render/README.md)
  — the renderer's exact contracts, refusals, and the `resume` semantics;
  [`docs/deployment.md`](../deployment.md#systemd) — install and the
  per-handle unit.
