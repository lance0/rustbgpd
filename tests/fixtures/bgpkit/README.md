# BGPKIT differential fixtures

These small, deterministic fixtures exercise the public `bgpkit-parser`
0.19.0 parser boundary. They are offline parser-contract data, not an
interoperability, compatibility, performance, or arbitrary-corpus claim.

Run the production-codec regeneration and byte-equality check with:

```console
REGENERATE_BGPKIT_FIXTURES=1 cargo test --locked --test bgpkit_differential fixtures_are_production_codec_reproducible -- --exact --nocapture
```

The regeneration path writes only these three files:

- `clean_ipv4_update.bin` uses `rustbgpd_wire::UpdateMessage::build` and
  `UpdateMessage::encode`. Its fixed IPv4 NLRI is `203.0.113.0/24`, next hop
  is `192.0.2.1`, AS_SEQUENCE is `[64512, 64513]`, standard communities are
  `[64512:10, 64512:20, 64512:10]`, and large communities are
  `[64512:100:1, 64512:200:2]`. Both community attributes carry Partial.
- `table_dump_v2.bin` uses
  `rustbgpd_mrt::codec::{encode_peer_index_table, encode_rib_entries}`. It
  contains one AS4 IPv4 peer and one legacy `RIB_IPV4_UNICAST` row carrying
  the clean attributes, with fixed timestamp `1700000000`, sequence `7`,
  collector ID `192.0.2.254`, and view name `bgpkit-oracle`.
- `bmp_v3_route_monitoring.bin` uses
  `rustbgpd_bmp::codec::encode_route_monitoring` with `BmpVersion::V3`, fixed
  global-peer metadata, timestamp `1700000000`, and the clean UPDATE.

`as_set_ipv4_update.bin` is different by design. It is an immutable,
receive-side-only 57-byte test vector. RFC 4271 §§4.1 and 4.3 define its BGP
message and UPDATE framing, and RFC 6793 §4.1 supplies the four-octet ASN
interpretation. Its AS_PATH payload reuses the RFC 9774 ingress vector in
`crates/wire/src/attribute.rs`: AS_SEQUENCE `[65001]` followed by AS_SET
`[65002, 65003]`. The remaining fixed fields are next hop `192.0.2.1` and
`203.0.113.0/24`. No encoder or regeneration path produces it: rustbgpd's
production emitter intentionally rejects AS_SET advertisement under RFC 9774.
The test observes each parser independently; it does not equate BGPKIT's
acceptance and empty warning vector with rustbgpd's retained attribute and
TreatAsWithdraw disposition.

SHA-256:

```text
0f6c88c61dfb3bf02fea98f0a7cc8782821511dfe27ed842b930f8ed9463b7a9  as_set_ipv4_update.bin
e0851fd8b25a299c6285ed8f0a2e296bd1128e3f227e9d689ee6e5c61dbb216b  bmp_v3_route_monitoring.bin
596fa835bb771d8f627b6cd1567a1eece4cd229f7db82fda086255eedd379896  clean_ipv4_update.bin
de3975665cf6ac981ede3b81724f8486b33bee36c816f9ef73b1f638cc4e4ae1  table_dump_v2.bin
```

Scope is limited to IPv4 unicast without Add-Path, MP families,
confederations, or BMP v4. Comparisons cover prefix, ordered AS-path segment
kind and ASN order. Standard- and large-community collections are both sorted
without deduplication, but only the standard communities carry a duplicate
cardinality discriminator. Error strings are deliberately outside the contract.
