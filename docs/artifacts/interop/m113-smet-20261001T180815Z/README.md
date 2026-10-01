# M113: controlled SMET reflection receipt

This run proves EVPN Type 6 SMET reflection, withdrawal, malformed-input handling,
and recovery through rustbgpd using controlled raw BGP peers and an independent
TShark decoder.

The run passed on 2026-10-01 at 18:08 UTC: 41 protocol phases, 15 TCP connections,
and 46 reflected SMET NLRIs. The [result](result.json) records every sent and
received BGP message, expected phase events, successful capture checks, and zero
exit statuses for the runner, daemon, and capture process. All owned processes
were cleaned up. The capture recorded 443 packets with zero kernel drops.

## Identity and evidence

The [provenance](provenance.json) records daemon source
`ff234d1c987a207cfb595db96ad4210989bdb875`, the daemon and harness SHA-256 hashes,
compiler, lockfile hash, capture image digest, and independent decoder identity.
The daemon was built from a clean tree. The harness includes subsequent fixture
repairs; runtime source was unchanged.

- [Packet capture](m113.pcap): original captured bytes.
- [TCP payloads](payloads.tsv): pinned TShark extraction for bidirectional stream
  reconstruction and comparison with the raw-peer transcript.
- [Independent decoder output](reflected.pdml): TShark 4.2.2 decoding of reflected
  traffic, checked against every expected RD, Ethernet tag, source/group length
  and address, originator length and address, and complete flags octet.
- [Result](result.json): ordered phase expectations and exact reflected NLRI and
  path-attribute checks, including ORIGINATOR_ID and CLUSTER_LIST.

## Exercised behavior

The fixture covers IPv4 wildcard-source and IPv6 source-specific SMET routes,
zero-length wildcard fields, IPv4 and IPv6 originators, distinct-originator
identity, a flags-only replacement, lower-preference fallback, and last-path
withdrawal. Withdrawals reconstruct the route key with a zero flags byte.
An update-wide treat-as-withdraw case withdraws affected existing paths and
then recovers on the same session.

Six structural cases cover missing flags, an extra byte, and mixed source/group
families in both announcements and withdrawals. Each must reset its source
session without leaking malformed routes to the receiver, then recover through
a valid announcement and withdrawal after reconnecting that same peer. Receiver
barriers establish event ordering. Each case uses its own source identity so
the daemon's intentional repeated-notification backoff remains unchanged.

Three normal peers and six reset-test sources use loopback addresses. This is a
small controlled control-plane fixture. It does not establish vendor
interoperability, scale, forwarding, SMET origination, IGMP/MLD proxy behavior,
or support for route types 7–11. EVPN remains alpha.

## Replay and reproduction

From the repository root, replay the saved evidence without capture privileges,
containers, a daemon, or an installed TShark:

```sh
python3 tests/interop/scripts/m113_smet_oracle.py \
  --replay docs/artifacts/interop/m113-smet-20261001T180815Z
```

CI runs this replay and the oracle's negative controls. Follow the
[M113 procedure](../../../../tests/interop/m113-smet-reflection/README.md) for a
new live run with the pinned tools.

The public PDML normalizes only its root `capture_file` attribute to `m113.pcap`
and removes a generated stylesheet-location comment. Every packet element and
decoded field is unchanged. Provenance records both original and public PDML
hashes; the public result uses the public hash. PCAP and TCP payload bytes are
unchanged. Runtime configuration, state, and local process logs are not part of
this portable receipt.
