# rs-config-render

Render rustbgpd route-server configuration from [arouteserver]
`template-context` output
([ADR-0110](../../docs/adr/0110-irr-peeringdb-filtering-pipeline.md)).

arouteserver already does the industry's IRR/PeeringDB/RPKI ingest —
bgpq4 against IRRd mirrors with failover, PeeringDB max-prefix and
as-set lookup, RPKI ROAs as route objects, per-source caching. Its
`template-context` command dumps that fully-resolved data model as
YAML. This tool consumes the dump and emits rustbgpd configuration, so
an IXP keeps its existing `general.yml`/`clients.yml` workflow and
adds exactly one render step:

```console
$ arouteserver template-context --output /var/lib/rs/context.yml
$ rs-config-render --context /var/lib/rs/context.yml \
    --out-dir /var/lib/rs/candidate --rtr-cache 127.0.0.1:3323
$ rustbgpd --check --strict /var/lib/rs/candidate/config.toml
```

Rendered output passes `--strict` — every member session carries an
explicit import chain and the declared transparent export chain (RFC 7947
permit-all, plus `ebgp_requires_policy` so deleting it fails closed) — so
the refresh loop can gate on warnings, not just on rejection.

[arouteserver]: https://github.com/pierky/arouteserver

## IXP Manager v7.4 manual candidate

The GPL-2.0-only Foil exporter under
[`integrations/ixp-manager`](../../integrations/ixp-manager/gpl-2.0-only/README.md)
runs inside IXP Manager and emits the versioned JSON boundary. Fetch that JSON
separately with authenticated `curl` into a mode-0600 file; the renderer does
not fetch URLs or handle API keys.

The supported render command is:

```console
umask 077
sudo -u rustbgpd /usr/bin/rs-config-render \
  --input-format ixp-manager-v1 \
  --context /var/lib/rustbgpd/ixp-manager/router.json \
  --out-dir /var/lib/rustbgpd/ixp-manager/candidate \
  --router-handle rs1-ipv4 \
  --runtime-state-dir /var/lib/rustbgpd/rs1-ipv4 \
  --max-prefix-restart-seconds 300 \
  --check-with /usr/bin/rustbgpd
```

The input must be a regular, non-symlink mode-0600 file. The output directory
must be absent or an empty, non-symlink mode-0700 directory; generated
configuration and policy files are mode 0600. Keep the input, candidate, and
activation-state parent owned by the `rustbgpd` service identity shown here.
IXP Manager mode always runs the selected binary first as `rustbgpd --version`
and then as `rustbgpd --check --strict <candidate>/config.toml`. Child output is
suppressed so authentication values cannot escape through diagnostics.

`render-receipt.json` is written last and only after the strict check passes.
It records the source identity and hash, generated-file hashes and counts,
refusal status, checked rustbgpd version, router handle, and exact runtime-state
directory without copying secrets. The generated config fixes the gRPC UDS at
`<runtime-state-dir>/grpc.sock`. A
candidate without that receipt is incomplete and must not be deployed.

After reviewing a complete candidate, install `config.toml` and its `policy/`
directory together using the existing coordinated-file procedure, then SIGHUP
rustbgpd. A failed export, refusal, render, or check leaves the running daemon
untouched. This render mode does not fetch or call IXP Manager update/release
callbacks.

### Atomic local activation

After review, activate a complete private candidate with an exact executable
and literal arguments (never a shell command):

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
  --activation-arg reload-or-restart --activation-arg rustbgpd
```

The service must read
`/var/lib/rustbgpd/rs1-ipv4/activation/current/config.toml`. The runtime path
basename must equal the router handle, and the activation path must be exactly
`<runtime-state-dir>/activation`. The state path
must be absolute, pre-created as a non-symlink mode-0700 directory, and owned by
the `rustbgpd` account. Keep the candidate and state exclusively writable by
that identity; do not run another publisher or reloader concurrently. Use
`--initial` only when no current generation and no reachable daemon exist.
Normalized comparison TOML is capped at 4,194,299 bytes so its encoded request,
including five bytes of protobuf overhead, remains within 4 MiB.

The helper rechecks a private immutable generation, atomically renames the
relative `current` symlink, runs one synchronous executable, and requires both
`rbgp health` and `rbgp config diff` to settle. Equal content is a no-op. Exit 4
is limited to a command that could not start: the helper restores the prior
link without a second activation and verifies the unchanged prior runtime. Once
the command starts, a nonzero exit, timeout, or unsettled runtime leaves
`current` on the candidate and returns exit 5 for explicit operator recovery.

Authorize the `rustbgpd` account in sudoers for only the exact
`/usr/bin/systemctl reload-or-restart rustbgpd` command. The private
`activation-receipt.json` is written last; generations are retained for
operator inspection. Exit 0 means activated or no-op, 2 refusal, 4 proven
pre-effect restoration, and 5 means recovery or receipt durability is
unproven. A receipt may
therefore be absent or stale after exit 5. The helper does not deploy services,
prune generations, retry indefinitely, or call IXP Manager. These examples use
package paths; release archives install the three binaries under `/usr/local/bin`.

### Authenticated IXP Manager lifecycle

`ixp-manager-lifecycle run` wraps the pinned IXP Manager v7.4 router API around
the same renderer and atomic activation path. It acquires the upstream router
lock, fetches the real Foil JSON over HTTPS, renders and strictly checks a fresh
private candidate, activates it, then delivers `updated` or
`release-update-lock` as appropriate:

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
  --activation-arg reload-or-restart --activation-arg rustbgpd
```

Supply a new absent or empty mode-0700 candidate directory for each run. The
absolute runtime, activation, and shared host-state directories must already
exist at mode 0700 and remain owned by
the `rustbgpd` identity. The API-key path must be absolute, regular,
non-symlink, mode 0600, and at most 4 KiB. The value appears only in the
`X-IXP-Manager-API-Key` request header: it is not accepted in argv or the
environment and is not retained in the lifecycle journal, render receipt,
capture, output, or diagnostics.

HTTPS with platform trust roots is mandatory. Redirects and environment
proxies are disabled. `--allow-http-loopback` exists only for a numeric
loopback test origin; hostname HTTP, `localhost`, URL credentials, query
strings, fragments, and path-prefixed origins are refused. Requests use a
bounded 1–300 second deadline, 32 KiB response-header ceiling, 64 KiB control
body ceiling, and 4 MiB configuration ceiling.

Lifecycle intent is written and synced before every upstream request. Exit 0
means `updated` was delivered. Exit 2 means no lock was acquired or a definite
pre-activation refusal was released. Exit 4 means the activation command never
started, exact prior runtime was proven, and release was delivered. Exit 5
does not issue a callback because lock acquisition or an activation effect is
uncertain. Exit 6 leaves one durable `updated` or release callback pending.

Every activation or lifecycle command also takes one advisory lock in the
shared host-state directory. A synced owner fence remains after process death,
ambiguous lock acquisition, activation recovery, or a pending callback. A new
run returns exit 5 while any fence exists; only `resume` with the exact same
handle, runtime, activation, host-state, and UDS binding may continue. A proven
terminal journal cleanup is synced before that matching fence is removed.

Retry only the pending callback with the same identity:

```console
sudo -u rustbgpd /usr/bin/rs-config-render ixp-manager-lifecycle resume \
  --ixp-origin https://ixp.example.net --router-handle rs1-ipv4 \
  --api-key-file /var/lib/rustbgpd/ixp-manager/api-key \
  --runtime-state-dir /var/lib/rustbgpd/rs1-ipv4 \
  --state-dir /var/lib/rustbgpd/rs1-ipv4/activation \
  --host-state-dir /var/lib/rustbgpd/ixp-manager-host \
  --rbgp-addr unix:///var/lib/rustbgpd/rs1-ipv4/grpc.sock
```

Callback delivery is at-least-once because IXP Manager v7.4 supplies no lease
or idempotency token. `resume` never refetches, rerenders, or activates. It has
no automatic action for exit 5; inspect retained activation/lifecycle state and
the live daemon before explicitly resolving the upstream router lock.

Release tarballs (`rustbgpd-<arch>.tar.gz` on the [releases
page](https://github.com/lance0/rustbgpd/releases)) ship the
`rs-config-render` binary alongside `rustbgpd` and `rbgp`; from
source, `cargo build --release -p rs-config-render`.

The end-to-end operator walkthrough — arouteserver through the
Alice-LG looking glass — is
[`docs/cookbook/ixp-filter-pipeline.md`](../../docs/cookbook/ixp-filter-pipeline.md).

## Input formats

The renderer auto-detects and ingests both on-disk forms of
`template-context` output:

- **The sectioned report** — what `arouteserver template-context`
  actually emits (pinned against 1.23.2): one section per context key,
  each a heading line plus a dash underline followed by a YAML
  fragment. Ingestion normalizes the report's quirks into the internal
  model: the `*_whois_db_records` section names, `irrdb_info` as a
  list of hash-keyed bundles, and per-client `as_set_bundle_ids` as a
  YAML `!!set`. Overlapping bundles (arouteserver resolves both a
  client's AS-SET and its bare origin-ASN object) dedupe in the union.
- **A single YAML document** with the context's top-level keys — the
  form the test fixtures use and the shape the fingerprint below pins.

Both forms of the same site render identical output — proven per
commit against a checked-in real dump
([`tests/interop/m90-differential/context-sectioned.yml`](../../tests/interop/m90-differential/context-sectioned.yml)),
and against a live run of the pinned arouteserver image by
[`tests/interop/m90-differential/prove-context-ingestion.sh`](../../tests/interop/m90-differential/prove-context-ingestion.sh).

## What it emits

| File | Contents |
|---|---|
| `config.toml` | RS globals, RPKI cache servers, one `[[neighbors]]` per client: transparent `route_server_client` session, `role = "route_server"`, strict next-hop ownership, per-family max-prefix ceilings and OpenBGPD-style timed restart, per-client import policy chain, `per_client_best` (or Add-Path when the context enables it); plus `ebgp_requires_policy = true` and explicit transparent or blackhole-aware export chains |
| `policy/rs-hygiene.rpol` | Shared import hygiene: reject AS_SET segments (always the first term), invalid/private/reserved ASNs in the path, transit-free and never-via-route-servers ASNs, AS_PATH length cap, bogon and black-list prefixes, prefix-length windows, RPKI origin validation with RFC 8097 tagging |
| `policy/client-<id>.rpol` | The client's IRR-derived `prefix-set` and origin `asn-set`, one accept term (`route.origin-as in … && route.prefix in …`), and an unconditional reject tail |
| `render-receipt.json` | Render timestamp, context fingerprint, per-client set cardinalities, max-prefix ceilings and restart seconds, warnings |

Every generated `.rpol` file carries in-language `test` blocks derived
from the site's own data; `rbgp policy check` runs them.

Term ordering is a contract: the hygiene policy leads every client's
import chain and its first term rejects AS_SET segments, so per-client
origin enforcement is never evaluated on a path that still carries an
AS_SET (`route.origin-as` resolves AS_SET-terminated aggregates
leniently; the ordering makes that moot — see `docs/rpol-language.md`).

## The refresh loop

Fail-stale, never fail-open — the arouteserver deployment loop
transfers verbatim:

```bash
#!/bin/sh -e
# cron: refresh member filters (arouteserver caches govern data staleness)
arouteserver template-context --output "$STATE/context.yml"
rs-config-render --context "$STATE/context.yml" \
    --out-dir "$STATE/candidate" --rtr-cache 127.0.0.1:3323
rustbgpd --check --strict "$STATE/candidate/config.toml"
rsync -a --delete "$STATE/candidate/" /etc/rustbgpd/
systemctl reload rustbgpd        # SIGHUP: parse-then-swap
```

Any step failing (arouteserver exit, render refusal/abort, `--check
--strict` rejection or warning) leaves the previous configuration
running untouched; the
daemon's own reload seam guarantees a bad swap can never evict working
policy either. Alert on the age of `render-receipt.json` — a pipeline
stuck for more than a couple of refresh intervals should page, not rot.

## Failure policy

Distinct exit codes, so the cron wrapper can tell "fix the renderer"
from "fix the data":

| Exit | Meaning |
|---|---|
| 1 | unreadable/unparseable context |
| 2 | **refused** — the context uses a knob the renderer will not silently drop |
| 3 | **aborted** — a generated set is empty or under the plausibility floor |
| 4 | **shape mismatch** — the context's top-level structure (document keys or report sections) drifted from the pinned fingerprint |

Refused knobs: RTT-based communities and `rtt_thresholds` (the daemon
has no RTT source; permanent), configured
`communities.rpki_bgp_origin_validation_not_performed` tagging (the renderer
cannot reproduce its tagging and inbound anti-spoof scrubbing), `next_hop.policy` other
than `strict`
(`same-as` needs the deferred fleet-inventory mode), `reject_policy`
`tag`/`tag_and_reject` (reject-reason community wiring is a tracked
follow-up; the daemon retains rejected routes with reasons natively —
see the route-server cookbook's filtered-route view), `prepend_rs_as`,
`perform_graceful_shutdown`, `max_prefix.action` `block`/`warning`,
and an effective `max_prefix.count_rejected_routes: true` while a positive
shutdown or restart limit is active (ARouteServer 1.23.2 defaults this option to true,
while rustbgpd counts accepted routes only),
per-client `black_list_pref` and IRR `white_list_*` entries (dropping
a black list would fail open; dropping a white list would reject
routes the site intends to accept), and disabling both IRR
enforcement knobs. `shutdown` emits the positive family ceilings;
`restart` additionally requires a positive `restart_after` in minutes, checked
while converting to `u32` seconds. An absent action or zero family limits emit
neither ceilings nor a restart timer.

The renderer also refuses effective nonzero multihop and RFC 8950 on an
IPv6 session. Blackhole policies support `propagate-unchanged` and
`rewrite-next-hop`. Active-family marked routes must have an IRR-authorized
origin and fall under a separately widened IRR covering set; this bypasses
ordinary maximum-length and RPKI rejection only after shared AS-path, bogon,
and blacklist hygiene. Export policy normalizes standard, large, and extended
local markers to `BLACKHOLE`, scrubs only those configured local markers,
honors client-over-general `announce_to_client`, optionally adds `NO_EXPORT`,
and applies the family-specific rewrite. The emitted global setting is
`honor_blackhole = false`; the renderer never relies on its implicit
`NO_ADVERTISE` behavior. Unknown policies, malformed markers, and missing or
wrong-family rewrite addresses refuse before output.

An empty per-client prefix or origin set aborts the whole render: an
empty set under the default-reject tail is fail-closed for that client,
and an empty upstream IRR answer almost always means broken data, not a
member that deregistered everything. Raise the floor with
`--min-prefixes`/`--min-origins` to also catch implausible shrinkage.

The context shape is not a semver-stable API. The renderer fingerprints
the top-level structure — document keys for the single-document form,
section names for the sectioned report — and refuses on drift, naming
the added and missing entries; `--allow-shape-drift` proceeds after
review. The supported shapes are pinned in `EXPECTED_TOP_LEVEL_KEYS`
and `EXPECTED_SECTION_NAMES` (`src/lib.rs`).

## Options

```text
--context <PATH>       template-context output (YAML; JSON parses too)
--out-dir <DIR>        output directory
--rtr-cache <ADDR>     RTR cache host:port, repeatable; required when the
                       context enables RPKI origin validation (the context
                       carries no cache address)
--min-prefixes <N>     per-client prefix-set plausibility floor (default 1)
--min-origins <N>      per-client origin-set plausibility floor (default 1)
--allow-shape-drift    proceed despite a fingerprint mismatch
--extra-rpol <PATH>    exact site-local policy bytes; repeatable
--merge-toml <PATH>    one strict site-local hook file (requires --extra-rpol)
```

## Local customization

The renderer owns the whole output directory — do not hand-edit generated
files. Supply one or more site policies together with exactly one merge file:

```console
rs-config-render --context context.yml --out-dir candidate \
  --extra-rpol site-global.rpol --extra-rpol site-peer.rpol \
  --merge-toml site-hooks.toml --rtr-cache 127.0.0.1:3323
```

```toml
[policy]
import_chain = ["site-global-in"]
export_chain = ["site-global-out"]

[[neighbors]]
address = "192.0.2.11"
import_policy_chain = ["site-peer-in"]
export_policy_chain = ["site-peer-out"]
```

This is intentionally not arbitrary TOML. Only those hook keys are accepted,
every hook must name a supplied policy, each final direction chain is unique,
and every policy must be used. Imports, datasets, parameters, generated-name collisions,
next-hop changes, AS prepends, community removals or variables, and configured
BLACKHOLE-marker synthesis are refused. The renderer validates and compiles the
whole bundle in memory before touching the output directory, emits exact source
bytes as `policy/site-local-NNN.rpol`, and attests source/emitted/config hashes
and requested/final chains under `site_local` in the receipt. Generated safety
always stays final: import is hygiene, global hook, neighbor hook, client deny;
export is global hook, neighbor hook, then transparent or BLACKHOLE base.
