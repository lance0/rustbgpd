# IXP filter pipeline: arouteserver → rs-config-render → rustbgpd → Alice-LG

Build an IXP filter pipeline around rustbgpd.

The toolchain an IXP already runs — [arouteserver] for
IRR/PeeringDB/RPKI member-filter generation, a looking glass for
member support — end to end on rustbgpd. You keep your existing
`general.yml` / `clients.yml` and the arouteserver refresh cadence;
rustbgpd replaces only the daemon, via one render step
([`tools/rs-config-render/`](../../tools/rs-config-render/README.md),
[ADR-0110](../adr/0110-irr-peeringdb-filtering-pipeline.md)).

This is the **ARouteServer-driven** provisioning mode. With no external
member source, hand-write the [IXP route server](route-server.md) instead;
with IXP Manager v7.4 as the member database, use the
[IXP Manager route server](ixp-manager-route-server.md) — the three-way
fork is in the [cookbook index](README.md#ixp-provisioning-three-modes).

The pipeline:

```text
general.yml + clients.yml
        │  arouteserver template-context     (IRR/PeeringDB/RPKI ingest)
        ▼
context.yml
        │  rs-config-render                  (fail-stale rendering)
        ▼
config.toml + policy/*.rpol + datasets/*.list + render-receipt.json
        │  rustbgpd --check --strict         (full config validation)
        ▼
swap + SIGHUP                                (parse-then-swap reload)
        │
        ▼
rbgp verification  +  Alice-LG via the birdwatcher adapter
```

This recipe assumes the [route-server cookbook](route-server.md)
shapes: transparent `route_server_client` sessions, RFC 9234
`route_server` role, per-client best-path. Migration mapping from an existing
BIRD/OpenBGPD deployment—including the manual OpenBGPD advertised-view
boundary—is in [route-server-migration.md](route-server-migration.md).

## 1. Generate the resolved member data

arouteserver's `template-context` command dumps its fully resolved
data model — bgpq4-expanded IRR prefix/origin sets, PeeringDB
max-prefix ceilings, RPKI knobs — as YAML, using your existing site
files and caches:

```bash
arouteserver template-context --output /var/lib/rs/context.yml
```

Install and configure arouteserver itself per its
[documentation][arouteserver] (`arouteserver setup`, then your
`general.yml` / `clients.yml`).

rustbgpd implements ARouteServer's shutdown, OpenBGPD-style timed-restart,
`block`, and `warning` actions. ARouteServer's BIRD target
restarts immediately and ignores `restart_after`; this is not BIRD timed parity.
`block` renders `max_prefix_action = "block"` (net-new prefixes beyond the
bound are withheld while the session stays Established) and `warning` renders
`max_prefix_action = "warning"` (one warning per crossing, no teardown).
Configure the model explicitly:

```yaml
cfg:
  filtering:
    max_prefix:
      action: restart
      restart_after: 15 # ARouteServer minutes; rendered as 900 seconds
      count_rejected_routes: false
```

An absent effective action disables max-prefix enforcement even when
ARouteServer leaves resolved limit values in the context; a zero family
limit is likewise treated as unset, and a restart timer is emitted only with a
positive family limit. `count_rejected_routes` selects the counting model:
ARouteServer 1.23.2 defaults it to `true`, which renders the pre-policy
`max_prefixes_received_ipv4`/`_ipv6` bounds (every unicast prefix the member
announces counts, accepted or rejected); `false` renders the accepted-route
`max_prefixes_ipv4`/`_ipv6` bounds.

The command's output format is arouteserver's, not ours: 1.23.2 emits
a *sectioned report* (per-key heading plus a YAML fragment). The
renderer auto-detects and ingests that form directly, alongside the
single-document YAML equivalent its fixtures use — no conversion step.
This exact pipeline runs for real against the pinned official
arouteserver image in
[`tests/interop/m90-differential/prove-context-ingestion.sh`](../../tests/interop/m90-differential/prove-context-ingestion.sh),
which asserts both input forms render identical configuration.

## 2. Render rustbgpd configuration

```bash
rs-config-render --context /var/lib/rs/context.yml \
    --out-dir /var/lib/rs/candidate --rtr-cache 127.0.0.1:3323
```

This emits `config.toml` (one `[[neighbors]]` per client with
per-family max-prefix ceilings and a per-client import chain),
`policy/rs-hygiene.rpol` (the shared hygiene chain: AS_SET reject,
bogons, transit-free, path-length cap, RPKI origin validation),
`policy/client-<id>.rpol` (the client's IRR-derived prefix/origin
tests and dataset bindings), `datasets/client-<id>-origins.list` and
`datasets/client-<id>-prefixes.list` (the generated IRR membership, plus a
blackhole-cover dataset when configured), and `render-receipt.json`
(fingerprint, cardinalities,
warnings). `--rtr-cache` is required whenever the context enables
RPKI origin validation — the context carries no cache address. The
renderer ships in the release tarball alongside `rustbgpd` and `rbgp`
([install](../deployment.md#install)); from a checkout, build it with
`cargo build --release -p rs-config-render`.

The renderer is deliberately fail-stale, never fail-open: a refused
knob (exit 2), an implausibly empty IRR set (exit 3), or context-shape
drift (exit 4) aborts the whole render and leaves the previous
configuration running. The full refused-knob table and failure policy
are in the [renderer README](../../tools/rs-config-render/README.md).

### Try it from this repository

The renderer's checked-in test fixture is a three-client context whose
third client deliberately carries an empty IRR prefix set, so a render
demonstrates the fail-closed abort:

```console
$ cargo run -q -p rs-config-render -- \
    --context tools/rs-config-render/tests/fixtures/context-small.yml \
    --out-dir /tmp/rs-out --rtr-cache 127.0.0.1:3323
rs-config-render: render aborted — implausible generated sets:
  - client AS51325_1 (AS51325): 0 IRR prefix(es) resolved, floor is 1 — an empty or shrunken set means the upstream IRR answer is broken, not that the client deregistered everything
no output written; the last good configuration stays live (fail-stale)
```

What a *successful* render of the same context (minus the broken
client) emits is checked in verbatim as the golden outputs —
[`tools/rs-config-render/tests/golden/`](../../tools/rs-config-render/tests/golden/):
`config.toml`, `rs-hygiene.rpol`, two `client-*.rpol` files, and each
client's origin and prefix dataset files. The test maps the flat checked-in
fixture names to their rendered `policy/` and `datasets/` paths. The
generated policies carry in-language `test` blocks derived from the
site's own data, runnable offline:

```console
$ rbgp policy check tools/rs-config-render/tests/golden/rs-hygiene.rpol
tools/rs-config-render/tests/golden/rs-hygiene.rpol: 7 passed, 0 failed
```

## 3. Validate, swap, reload

The deployment loop is the same fail-stale cron shape arouteserver
deployments already use — every step must succeed or the previous
configuration stays live:

```bash
#!/bin/sh -e
# cron: refresh member filters (arouteserver caches govern data staleness)
arouteserver template-context --output "$STATE/context.yml"
rs-config-render --context "$STATE/context.yml" \
    --out-dir "$STATE/candidate" --rtr-cache 127.0.0.1:3323
# --strict: warnings fail the gate, so a refresh never swaps in a config
# the daemon had something to say about. Rendered output is clean.
rustbgpd --check --strict "$STATE/candidate/config.toml"
# The generated rpol resolves dataset paths relative to this tree. Install the
# config, policy, and datasets together; never update only one directory.
rsync -a --delete "$STATE/candidate/" /etc/rustbgpd/
systemctl reload rustbgpd        # SIGHUP: parse-then-swap
```

Before the first cutover — or any time you want to see what a refresh
will change — preview the candidate against the running daemon:

```bash
rbgp config diff /var/lib/rs/candidate/config.toml
```

Each changed field is annotated hot-applied / session reset / restart
required. The daemon's reload is itself parse-then-swap: a config that
fails to parse or validate at SIGHUP leaves the running configuration
untouched, so a bad swap can never evict working policy.

Run the loop at the cadence your IRR data actually changes —
arouteserver deployments typically refresh every 6–24 hours, and the
renderer adds no reason to differ. The arouteserver cache TTLs govern
data staleness; the refresh script above only re-renders what those
caches resolve.

`rs-config-render` distinguishes its failure classes by exit code so
the cron wrapper can alert on *why* the loop is stuck, not just that
it is:

| Exit | Meaning | Operator action |
|------|---------|-----------------|
| `0` | Rendered; receipt written | none |
| `1` | Context parse error | inspect the `template-context` output |
| `2` | Refused — unsupported context knobs (listed on stderr) | remove the knob or wait for renderer support; repeats every run until the site config changes |
| `3` | Implausible data — empty/collapsed member sets | usually an upstream IRR/PeeringDB outage; the previous config stays live by design |
| `4` | Context shape mismatch — arouteserver output changed | pin the arouteserver version or update the renderer |

Exit `3` is the fail-stale case the pipeline exists for: a transient
upstream outage must never strip a member's filters, so nothing is
emitted and the daemon keeps serving the last good generation.

Alert on the age of `render-receipt.json` — a pipeline stuck for more
than a couple of refresh intervals should page. The matching
daemon-side signal is `bgp_policy_generation_loaded_timestamp_seconds`
("Policy artifact freshness" in [OPERATIONS.md](../OPERATIONS.md)),
which deliberately stays frozen when a reload is rejected — file
mtimes can lie about what the daemon actually accepted.

## 4. Verify member sessions and filters

```bash
rbgp summary                          # members Established
rbgp rib received 198.51.100.2        # a member's accepted routes
rbgp policy stats                     # hygiene/client terms firing
rbgp policy explain --neighbor 198.51.100.2 --prefix 203.0.113.0/24
```

The last one needs `[policy.explain] enabled = true` — import explain is
opt-in, since the decision cache is per session and its cost multiplies
by member count. Without it the query answers `cache_disabled` and names
the lines to add.

## 5. Member support: the filtered-route view

The daemon retains each member's rejected routes with canonical
reason tokens — the "which of my routes are you filtering, and why"
answer, queryable without knowing a prefix in advance:

```bash
rbgp rib received 198.51.100.2 --rejected
```

The [route-server cookbook](route-server.md#member-support-the-filtered-route-view)
covers this view, its retention knobs, and the follow-up explain
workflow; the full explain surface catalog is in
[explain.md](../explain.md).

<a id="6-looking-glass-alice-lg-via-the-birdwatcher-adapter"></a>
## 6. Alice-LG via the birdwatcher adapter

Alice-LG uses the external
[`examples/birdwatcher-adapter`](../../examples/birdwatcher-adapter/README.md)
sidecar, which serves a Birdwatcher-shaped REST subset from the daemon's gRPC
API —
status, peers, a member's accepted routes, the filtered-route view
above, and a noexport view (routes withheld from a member, each named
by the export gate that stopped it, tagged `64496:65521:<id>`). For the
filtered view it synthesizes one reject-reason large
community (`64496:65520:<id>`, one stable id per reason token) on each
route, matchable by Alice-LG's `[rejection_reasons]` config exactly
like arouteserver's reject-reason tagging on BIRD; the adapter README
carries the mapping table and a ready Alice-LG config snippet.

```bash
cargo run --release -p birdwatcher-adapter -- \
    --grpc-addr unix:///var/lib/rustbgpd/grpc.sock \
    --listen 0.0.0.0:8080
```

The owner-only socket is convenient but grants operator-tier `local-operator`;
the adapter README shows a dedicated token-authenticated `observer` listener
for least privilege. The adapter also needs
`[policy.reject_retention]` enabled for the filtered view. The noexport
view is served from the export-explain surface (best-routes-minus-
advertised, one export-ladder dry run per suppressed prefix). Honest
boundary: this is a maintained single-table unicast subset — a few
Birdwatcher fields are served as sentinels (the adapter README lists
every gap).

The pinned compatibility gate exercises this wiring through Alice-LG 6.2.0:
four live neighbor IDs, seven accepted routes, empty filtered arrays, and the
labeled `192.0.2.0/24` split-horizon noexport route. A pinned MANRS consumer
then traverses Alice's received routes and finds one deliberate synthetic ROA
mismatch. After freezing that baseline, the gate runtime-adds a fifth live
member, atomically reloads the adapter alias, and restarts Alice to clear its
caches. The four original peers and seven routes remain unchanged; the fifth
peer has an empty accepted view and exactly one filtered `198.18.0.0/24` with
`64496:65520:4`, joined through `/config.reject_reasons` to `Receiver AS
appears in AS_PATH`. That is a backend/API proof, not a rendered-browser,
MANRS certification, rustbgpd RPKI-enforcement, or route-server-policy-
conformance claim.

[arouteserver]: https://github.com/pierky/arouteserver
