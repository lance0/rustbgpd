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
