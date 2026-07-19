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
$ rustbgpd --check /var/lib/rs/candidate/config.toml
```

[arouteserver]: https://github.com/pierky/arouteserver

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
| `config.toml` | RS globals, RPKI cache servers, one `[[neighbors]]` per client: transparent `route_server_client` session, `role = "route_server"`, strict next-hop ownership, per-family max-prefix ceilings, per-client import policy chain, `per_client_best` (or Add-Path when the context enables it) |
| `policy/rs-hygiene.rpol` | Shared import hygiene: reject AS_SET segments (always the first term), invalid/private/reserved ASNs in the path, transit-free and never-via-route-servers ASNs, AS_PATH length cap, bogon and black-list prefixes, prefix-length windows, RPKI origin validation with RFC 8097 tagging |
| `policy/client-<id>.rpol` | The client's IRR-derived `prefix-set` and origin `asn-set`, one accept term (`route.origin-as in … && route.prefix in …`), and an unconditional reject tail |
| `render-receipt.json` | Render timestamp, context fingerprint, per-client set cardinalities and max-prefix ceilings, warnings |

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
rustbgpd --check "$STATE/candidate/config.toml"
rsync -a --delete "$STATE/candidate/" /etc/rustbgpd/
systemctl reload rustbgpd        # SIGHUP: parse-then-swap
```

Any step failing (arouteserver exit, render refusal/abort, `--check`
rejection) leaves the previous configuration running untouched; the
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
has no RTT source; permanent), `next_hop.policy` other than `strict`
(`same-as` needs the deferred fleet-inventory mode), `reject_policy`
`tag`/`tag_and_reject` (reject-reason community wiring is a tracked
follow-up; the daemon retains rejected routes with reasons natively —
see the route-server cookbook's filtered-route view), `prepend_rs_as`,
`perform_graceful_shutdown`, `max_prefix.action` `restart`/`block`/`warning`,
and an effective `max_prefix.count_rejected_routes: true` while a positive
shutdown limit is active (ARouteServer 1.23.2 defaults this option to true,
while rustbgpd counts accepted routes only),
per-client `black_list_pref` and IRR `white_list_*` entries (dropping
a black list would fail open; dropping a white list would reject
routes the site intends to accept), and disabling both IRR
enforcement knobs. Only `max_prefix.action: shutdown` is rendered;
an absent effective action emits no max-prefix ceilings, and zero is
treated as an unset per-family limit.

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
```

## Local customization

The renderer owns the whole output directory — do not hand-edit
generated files. Site-local policy belongs in a separate `.rpol` file
appended to the daemon's `[policy] rpol_files` by your own tooling
after the rsync step, or in a wrapper that post-processes
`config.toml`; a first-class merge-in point is a tracked follow-up.
