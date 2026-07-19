# M90 — arouteserver differential lab (ADR-0110 phase 1)

One `general.yml`/`clients.yml` pair drives **both** route servers:

- **BIRD 2** gets its config from **arouteserver proper**, run
  containerized at lab runtime from the official `pierky/arouteserver`
  image;
- **rustbgpd** gets its config from
  [`tools/rs-config-render`](../../../tools/rs-config-render/README.md),
  fed the site's `arouteserver template-context` dump (`context.yml`).

Three GoBGP members (AS64500–AS64502) peer with both servers over a
bridged 192.0.2.0/24 peering LAN and announce the canned set in
[`announcements.json`](announcements.json). The lab proves that every
announcement gets an **identical accept/reject verdict on both
daemons**, and that for every rejection rustbgpd's
`rbgp policy explain` names the **generated policy term** the manifest
predicts (plus the canonical `policy_reject` reason token in
`rbgp rib received <member> --rejected`). The expected verdicts were
derived by hand from the renderer's emission logic — shared hygiene
policy first (its term order is fixed: AS_SET, never-via-RS, path
length, bogons, black list, prefix-length windows), then the
per-client IRR policy ending in a fail-closed `rest` term — so the
lab's job is to prove BIRD agrees with that reading.

The member roster covers three distinct outcomes:

| Member | ASN | Behavior | Rejecting term(s) |
|--------|-----|----------|--------------------|
| member1 | AS64500 | IRR-clean, but also announces the peering LAN | `rs-hygiene` / `reject-black-list-prefix` |
| member2 | AS64501 | announces outside its IRR set (another member's prefix, an unregistered more-specific) | `client-as64501-1` / `rest` |
| member3 | AS64502 | bogon, too-long prefix, default route, never-via-RS ASN in path | `reject-bogon-prefix`, `reject-v4-len-outside-window`, `reject-never-via-rs` |

## Running it

```bash
docker build --target dev -t rustbgpd:dev .
docker build -t bird:2-bookworm -f tests/interop/Dockerfile.bird tests/interop
docker build -t gobgp:interop -f tests/interop/Dockerfile.gobgp tests/interop
containerlab deploy -t tests/interop/m90-differential.clab.yml
bash tests/interop/scripts/test-m90-differential.sh
containerlab destroy -t tests/interop/m90-differential.clab.yml
```

The driver renders both configs itself (nothing is bind-mounted into
the route-server nodes): `arouteserver bird` in the pinned container
for BIRD, `cargo run -p rs-config-render` for rustbgpd, followed by
the pipeline's own gates (`rustbgpd --check`, `rbgp policy check` on
every generated `.rpol`).

**Image pin:** the driver runs
`pierky/arouteserver@sha256:ba0e9c0b541c63acf0765a08fd2e09c2bba9dc64af1f5bbdce7819e8d1c34d66`
(`:latest` as of 2026-07-18, arouteserver 1.23.2). Override with
`M90_ARS_IMAGE` to test another build.

## The canonical context path

`context.yml` is checked in hand-authored (matching the renderer's
fingerprint-pinned 17-key single-document shape, same as its golden
fixture) so the rustbgpd side renders deterministically offline.
arouteserver's own dump of the same site is

```bash
arouteserver template-context --cfg arouteserver.yml --output context.yml
```

(same mounts as the driver's BIRD render). As of arouteserver 1.23.2
that command emits a *sectioned report* (per-key heading + underline +
YAML fragment) whose section names and value shapes differ from the
single-document form (e.g. `arin_whois_db_records` vs
`arin_whois_records`; `irrdb_info` as a list of hash-keyed bundles vs
a map); `rs-config-render` auto-detects and ingests **both** forms. A
real dump from the pinned image is checked in verbatim as
[`context-sectioned.yml`](context-sectioned.yml), and
[`prove-context-ingestion.sh`](prove-context-ingestion.sh) re-runs the
dump against the pinned image and asserts, with true exit codes, that
it still matches the checked-in dump byte for byte and that both
fixtures render identical configuration (modulo the context-shape
fingerprint header). The renderer's test suite pins the same parity
offline.

The lab never trusts the fixtures alone: the BIRD side always re-runs
arouteserver proper from `general.yml`/`clients.yml` at runtime, so if
a fixture drifts from the site files the differential verdicts
diverge and the lab fails.

## Site quirks (deliberate)

- **Documentation ranges everywhere** (RFC 5398 ASNs, RFC 5737
  prefixes), per repo convention — which forces two site-level
  choices:
  - `reject_invalid_as_in_as_path: False` in `general.yml`: the
    documentation ASN blocks sit inside the invalid-ASN range both
    pipelines reject by default;
  - a lab-local [`bogons.yml`](bogons.yml): arouteserver's default
    bogons list rightly treats the RFC 5737 prefixes as bogons.
- **`bgpq4-stub.sh`** answers the IRR queries with canned data (the
  documentation AS-SETs have no live registry objects); its answers
  must stay in lockstep with the `irrdb_info` bundles in
  `context.yml`.
- RPKI origin validation is off — the differential under test is the
  IRR/hygiene pipeline; ROV interop has its own lab (M83).
- Both route servers carry the same BGP identifier (the one
  `router_id` in `general.yml` renders into both configs); they never
  peer with each other, so this is harmless.

## Verified M90 receipt — 2026-07-19

The lab was run from source revision
`f7ccc133e91c035df1f9536b1b6d6ad4e287ca63` with these immutable
runtime identities:

| Component | Version | Image identity |
|-----------|---------|----------------|
| arouteserver | 1.23.2 | `pierky/arouteserver@sha256:ba0e9c0b541c63acf0765a08fd2e09c2bba9dc64af1f5bbdce7819e8d1c34d66` |
| BIRD | 2.0.12 | `bird:2-bookworm`, image ID `sha256:5658f128964bce8aabe96703307aceff2d5fc883fbd86151c9b32d19b3559bcf` |
| GoBGP | 3.37.0 | `gobgp:interop`, image ID `sha256:a6d73539911988d9525930030a748019a584abfc5684986eeb9dd0d4d3c80f9a` |
| rustbgpd | 0.60.0 | `rustbgpd:dev`, image ID `sha256:b6bb41cbc2e008c7798fd5b7ed5a50a0474969a21d51fe0ee1272801363c7dfc` |

The exact fixture set was:

| Input | SHA-256 |
|-------|---------|
| `general.yml` | `cb718ea5bba676ddf0183e959d6479718b02e0ebe01428d5fce2d919d8f28306` |
| `clients.yml` | `08ceca5f9bafb13139538096a94595d075b7a7dae9342deb26d7f5adfc337e1e` |
| `context.yml` | `0af51e2ca17b1a9cd5556e7cddbf3549f658dcafc69ab2de9dd2240ec0e57c5c` |
| `context-sectioned.yml` | `66eb0765f3226359b28b83f891df0d3019339e5089f9664d60d377543fa55390` |
| `announcements.json` | `5e2050c0e5f758d8b4691af873fc618c03bc3ce3eb25d5c522306df908e1dd3d` |
| `bogons.yml` | `26e7c313a41fd7a854f73c656a77415fd9c2bb9057b625a7592bd436ee26dfe5` |
| `arouteserver.yml` | `c3b85f1af54c437ae50b0d4e1502b3a6e95cb2c4b12c255ac1c90cfc9eec5b19` |
| `bgpq4-stub.sh` | `cebb06da5c9adff5184652bca877ab7956f137c5d9cd425b7c449ad0e950bb84` |

Run commands were the six commands in [Running it](#running-it), plus:

```bash
bash tests/interop/m90-differential/prove-context-ingestion.sh
```

The context proof passed 15/15 checks: the fresh pinned-image sectioned
dump matched `context-sectioned.yml` byte for byte, both context shapes
rendered identical files, `rustbgpd --check` passed, and all four generated
policies passed `rbgp policy check`. The full differential passed 65/65
checks. All 11 manifest rows were accounted for (4 accepts, 7 rejects), with
per-member import counters exactly 2/1, 1/2, and 1/4 permitted/denied. All
three sessions remained Established with zero flaps. rustbgpd logged one
IPv4-unicast End-of-RIB toward each member before the announcement injection,
so the verdict matrix was evaluated after initial table completion.

| Member | Prefix | Verdict on both | rustbgpd deciding policy / term |
|--------|--------|-----------------|----------------------------------|
| AS64500 | `198.51.100.0/24` | accept | — |
| AS64500 | `203.0.113.0/27` | accept | — |
| AS64500 | `192.0.2.0/24` | reject | `rs-hygiene` / `reject-black-list-prefix` |
| AS64501 | `203.0.113.128/25` | accept | — |
| AS64501 | `198.51.100.0/24` | reject | `client-as64501-1` / `rest` |
| AS64501 | `203.0.113.192/26` | reject | `client-as64501-1` / `rest` |
| AS64502 | `203.0.113.64/26` | accept | — |
| AS64502 | `10.64.0.0/16` | reject | `rs-hygiene` / `reject-bogon-prefix` |
| AS64502 | `203.0.113.64/30` | reject | `rs-hygiene` / `reject-v4-len-outside-window` |
| AS64502 | `0.0.0.0/0` | reject | `rs-hygiene` / `reject-v4-len-outside-window` |
| AS64502 | `198.51.100.128/25` | reject | `rs-hygiene` / `reject-never-via-rs` |

Load-bearing proof: a temporary rust-side-only mutation authorized
`198.51.100.0/24` in `AS64501_bundle` in `context.yml`, while the BIRD input
remained unchanged. The driver exited 1 at
`rustbgpd retains rejected 198.51.100.0/24 from member2 ... timed out after
30s`; BIRD still rejected it. The mutation was removed byte for byte before
the final 65/65 green run. Removing either daemon's policy parity therefore
makes this receipt red instead of producing a false green.
