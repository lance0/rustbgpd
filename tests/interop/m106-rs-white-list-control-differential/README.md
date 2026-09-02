# M106 — arouteserver white-list / control-community differential lab

The [M90 differential](../m90-differential/README.md) re-run on a sibling
site: the same three GoBGP members (AS64500–AS64502), the same
`general.yml`/`clients.yml` pair driving **both** route servers (BIRD 2
rendered by arouteserver proper, rustbgpd rendered by
[`tools/rs-config-render`](../../../tools/rs-config-render/README.md) from
the site's `template-context` dump), plus the two renderer surfaces this
lab proves:

- **IRR white lists.** member1 carries a `white_list_pref` (a /25 outside
  its exact /24 route object) and a `white_list_asn` (origin 64510, not in
  its AS-SET); member2 carries a `white_list_route` bound to origin 64501
  for `198.51.100.0/25 le 26` — member1's space, absent from member2's
  AS-SET. The renderer folds the first two into the member's datasets and
  emits the third as an accept term ahead of IRR enforcement, tagged with
  the site's `route_validated_via_white_list` community and scrubbed in
  shared hygiene.
- **Control communities.** The site configures exactly the daemon's fixed
  RFC 7947 §2.3.2 / RFC 8195 matrix, so the rendered sessions keep
  `rs_control_communities` on. Rows tagged `0:64502` (do not announce to
  AS64502), `0:64496` + `64496:64501` (announce to none, except AS64501),
  and `64496:102:64502` (prepend twice toward AS64502) prove per-target
  suppression, the override ladder, prepending, and scrubbing.

The M90 fixtures stay untouched (M104 pins their hashes); this directory
holds its own copies of the site files with the additions above. The
manifest keeps the eleven M90 rows and adds eight:

| Member | Prefix | Verdict | rustbgpd policy / term | Exported to |
|--------|--------|---------|-------------------------|-------------|
| AS64500 | `198.51.100.128/25` | accept | `client-as64500-1` / `accept-authorized` (via `white_list_pref`) | — |
| AS64500 | `203.0.113.0/28`, path `64500 64510` | accept | `client-as64500-1` / `accept-authorized` (via `white_list_asn`) | — |
| AS64501 | `198.51.100.0/25` | accept | `client-as64501-1` / `accept-white-list-route-1` | AS64500 and AS64502, tagged `65530:2` + `64496:65530:2` |
| AS64501 | `198.51.100.0/27` | reject | `client-as64501-1` / `reject-irrdb-prefix-filtered` (cause 12) | — |
| AS64501 | `198.51.100.64/26`, path `64501 64500` | reject | `client-as64501-1` / `reject-irrdb-origin-as-filtered` (cause 9) | — |
| AS64500 | `203.0.113.32/27`, `0:64502` | accept | — | AS64501 only, community scrubbed |
| AS64500 | `203.0.113.48/28`, `0:64496` `64496:64501` | accept | — | AS64501 only, both scrubbed |
| AS64500 | `203.0.113.16/28`, `64496:102:64502` | accept | — | AS64501 with path length 1, AS64502 with path length 3, large community scrubbed |

Every row gets the M90 verdict assertions on both daemons; the rows with
an `export` block are additionally read back from each target member's
own Adj-RIB-In (`gobgp neighbor <route-server> adj-in`) from **both** route
servers, so BIRD is the oracle for the daemon's control-community matrix
as well as for the white lists.

## Running it

```bash
docker build --target dev -t rustbgpd:dev .
docker build -t bird:2-bookworm -f tests/interop/Dockerfile.bird tests/interop
docker build -t gobgp:interop -f tests/interop/Dockerfile.gobgp tests/interop
containerlab deploy -t tests/interop/m106-rs-white-list-control-differential.clab.yml
bash tests/interop/scripts/test-m106-rs-white-list-control-differential.sh
containerlab destroy -t tests/interop/m106-rs-white-list-control-differential.clab.yml
```

The driver carries the M90 driver's phases (render, start, inject,
verdicts) as a copy — the M90 script is an immutable asset pinned by M104 —
with community-carrying injection, explain checks on accept rows, and the
export phase added; the topology is the M90 one under its own name, reusing
the M90 GoBGP member configs. The offline half is

```bash
bash tests/interop/m106-rs-white-list-control-differential/prove-context-ingestion.sh
```

which re-dumps the site from the pinned arouteserver image, asserts the dump
still matches `context-sectioned.yml` byte for byte, renders both context
forms identically, and checks the control knob, white-list members, tagged
accept term, and hygiene scrub in the rendered output. The renderer's test
suite pins the same parity offline.

## Verified receipt

Run from this change set on base `7d82c569017d73a1e24ac1faa9d17444f22d44b2`
against pinned arouteserver 1.23.2
(`pierky/arouteserver@sha256:ba0e9c0b541c63acf0765a08fd2e09c2bba9dc64af1f5bbdce7819e8d1c34d66`),
BIRD 2.0.12 (`bird:2-bookworm`, image ID
`sha256:c8ea2e31454641e105d71c833a6d816607347a755e61e05ae4ed35418745c7d0`),
GoBGP 3.37.0 (`gobgp:interop`, image ID
`sha256:4575cbd773da6e98512cb82d369a7e7a1677883c80058a4b66caf21fcad12b62`),
and rustbgpd 0.68.0 built from the change (`rustbgpd:dev`, image ID
`sha256:ea00c22a548bc21de095045a441dfc57d942c5ed04047cdd007d27e2283759d3`).

The context proof passed 24/24 and the differential passed 142/142: all 19
rows (8 accepts, 11 rejects) agreed on both daemons, rustbgpd's explain
named the predicted policy and term for every reject and for the three
white-list accepts, BIRD's filtered routes carried the generic and cause
tags, every export expectation held at the members from both route servers,
and all six sessions survived.

| Input | SHA-256 |
|-------|---------|
| `general.yml` | `4853d77949235e28c167d01904b08d3fe4db5e30fa11da190870458cc608ee9d` |
| `clients.yml` | `489033c1fb48528529530ccc6bec6acc3b886d3ec249ff250e823225f4d4c32f` |
| `context.yml` | `423420a3dc44fae3d6d0f36cca9a83b758976304b9c3f33ae4f831292cb8b5c1` |
| `context-sectioned.yml` | `d094ea3c2f8f8e0b69ea1168dd51874a83b60219bbea54929061b21d9b3b5427` |
| `announcements.json` | `8cb6d1577735c3691d8543e5914a7cbc23c6a73d9b93525c890c7d63eacc5c55` |
| `bogons.yml` | `41f811890a0474f7f6d2310c3bdf51dc22882b83990cc23f37f308088eee94b8` |
| `arouteserver.yml` | `fd565a7c8a80a3023e7df27194d4f5f92e4cc79216fdd47152445fe383218660` |
| `bgpq4-stub.sh` | `ee85a8baedc4224e81a780c7ce92e3331f467ce7922008b5f1a2e56ea0e2bdfd` |

A first run with a wrong Adj-RIB-In field name for large communities failed
exactly the four tag assertions for `198.51.100.0/25` (138/142) and passed
everything else, so the tag check is load-bearing; the fixed driver passed
142/142 on a fresh deploy, and the self-contained driver as committed passed
142/142 again on another fresh deploy.
