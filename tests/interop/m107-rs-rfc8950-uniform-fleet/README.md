# M107 — RFC 8950 uniform-fleet route server

Two GoBGP members exchange IPv4 (and IPv6) unicast over **IPv6-only**
sessions through a transparent rustbgpd route server whose configuration
is rendered by [`tools/rs-config-render`](../../../tools/rs-config-render/README.md)
from an arouteserver site with `rfc8950: True` and only IPv6 members —
the uniform-fleet shape the renderer emits: every member session carries
both unicast families (`families = ["ipv4_unicast", "ipv6_unicast"]`, so
the extended next hop is negotiated) and `next_hop_ownership =
"strict_peer"` accepts an IPv4 route only with the announcing member's
own IPv6 address as its next hop. No node in the lab carries an IPv4
address.

The lab proves, from the members' own Adj-RIB-In and the route server's
accepted and rejected views:

- both members negotiate the Extended Next Hop capability with the exact
  (IPv4 unicast NLRI, IPv6 next hop) tuple;
- `strict_peer` accepts each member's IPv4 route with that member's IPv6
  address as the RFC 8950 next hop, and keeps the wire value;
- the same member's IPv4 route carrying the *other* member's IPv6 address
  is rejected before import policy with reason `next_hop_ownership` /
  `foreign_next_hop`, naming the violating next hop, and never reaches
  the other member;
- transparent export preserves the originating member's IPv6 next hop
  toward the other member for IPv4 and IPv6 routes alike — the route
  server's own address never appears.

A mixed fleet (an IPv4-session member alongside RFC 8950 members) is not
part of this lab: the renderer refuses that shape because it would need
the next-hop translation
[ADR-0128](../../../docs/adr/0128-route-server-next-hop-translation.md)
keeps demand-gated.

## Running it

```bash
docker build --target dev -t rustbgpd:dev .
docker build --build-arg TARGETARCH=amd64 --build-arg GOBGP_VERSION=4.8.0 \
  --build-arg GOBGP_SHA256=43b570ae5cc1afab7aebdd9d8f4536e27656465848270c8a6f5fda1ffe093a03 \
  -t gobgp:v4.8.0-m107 -f tests/interop/Dockerfile.gobgp-v47 tests/interop
containerlab deploy -t tests/interop/m107-rs-rfc8950-uniform-fleet.clab.yml
bash tests/interop/scripts/test-m107-rs-rfc8950-uniform-fleet.sh
containerlab destroy -t tests/interop/m107-rs-rfc8950-uniform-fleet.clab.yml
```

The driver renders the route server itself (`cargo run -p rs-config-render`
on `context.yml`), gates the output with `rustbgpd --check --strict` and
`rbgp policy check`, and only then starts the daemons; nothing is
bind-mounted into the route-server node. The offline half is

```bash
bash tests/interop/m107-rs-rfc8950-uniform-fleet/prove-context-ingestion.sh
```

which re-dumps the site from the pinned arouteserver image, asserts the dump
still matches `context-sectioned.yml` byte for byte, renders both context
forms identically, and checks the uniform-fleet shape in the rendered output.
The renderer's test suite pins the same parity offline.

## Site

| Member | ASN | Session | Route objects (bgpq4 stub) |
|--------|-----|---------|----------------------------|
| member1 | AS64500 | `2001:db8:107::11` | `198.51.100.0/24 le 25`, `2001:db8:1::/48` |
| member2 | AS64501 | `2001:db8:107::12` | `203.0.113.0/24`, `2001:db8:2::/48` |

Route server: AS64496 at `2001:db8:107::9`, BGP identifier `192.0.2.10`.
Documentation ranges throughout (hence `reject_invalid_as_in_as_path:
False` and the lab-local `bogons.yml`).

## Verified receipt

Run from this change set on base `7d82c569017d73a1e24ac1faa9d17444f22d44b2`
with GoBGP 4.8.0 (`gobgp:v4.8.0-m107`, checksum-pinned build, image ID
`sha256:eac87c29df50b7f721d4fbe660f43ea513eea1371827f9fc0369eab81cb715d0`)
and rustbgpd 0.68.0 built from the change (`rustbgpd:dev`, image ID
`sha256:ea00c22a548bc21de095045a441dfc57d942c5ed04047cdd007d27e2283759d3`);
the site was dumped by pinned arouteserver 1.23.2
(`pierky/arouteserver@sha256:ba0e9c0b541c63acf0765a08fd2e09c2bba9dc64af1f5bbdce7819e8d1c34d66`).

The differential passed 32/32 (the 25-point contract in the driver header
plus readiness and injection checks): the rendered config carried both
families, `strict_peer`, and an explicit `rs_control_communities` on both
sessions and passed every gate; both members negotiated the extended next
hop; the three owned routes were accepted with their wire next hops
(`2001:db8:107::11` / `::12`) intact; the foreign-next-hop route was
rejected as `next_hop_ownership` / `foreign_next_hop` naming
`2001:db8:107::12` and never reached member2; and each member received the
other's routes with the originator's IPv6 next hop.

| Input | SHA-256 |
|-------|---------|
| `general.yml` | `8a010b7fd62df430d79dca6defe2cf6ba0b1ee9257e580ac774a7d5b1ae62e66` |
| `clients.yml` | `f7e9512659082c2dd5b9ef872e72a7acf592ab9d853857f3c6f1f3d55bd80165` |
| `context.yml` | `b86e39954e59322a1743f2535dcc9082f1b3f1dc716d5158cab797e1555a7c7c` |
| `context-sectioned.yml` | `e211d6c14f2de0f8d2d4a60037402d9cfe51f0455784ae840c3c336ba5115b3c` |
| `bogons.yml` | `8084ba0758107163fdf66d938a81d87d2a407a05a063130fb9be8acd7480c658` |
| `arouteserver.yml` | `8d9eb82a0a7d5ec6b0ff129164881a520cb646ab90050b22ebe6bc203720dcc6` |
| `bgpq4-stub.sh` | `a87376068a517e7ce84bd26d3c967d9626e320e062ae0ba9fe0fafa3ba24cea9` |
| `configs/gobgp-m107-member1.toml` | `9c4c4a253780d4191eb11226f0c2fe5e5b5138129cb910f1fe0ee26df0586b62` |
| `configs/gobgp-m107-member2.toml` | `4171bc54798a00f6852d70489baa9e3f813d64fc2d53cce1851c4f0d14ee9092` |

A first run whose driver read the capability, rejected-store, and Adj-RIB-In
JSON at the wrong paths failed exactly those six assertions (23/29) while
the route server had already accepted the owned routes and rejected the
foreign one; the corrected driver passed 32/32 on a fresh deploy, and the
driver as committed passed 32/32 again on another fresh deploy.
