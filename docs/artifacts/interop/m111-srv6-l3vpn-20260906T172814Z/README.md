# SRv6 L3VPN reflection receipt

M111 passed on 2026-09-06 at 17:28 UTC with FRR 10.7.1 originating VPNv4
and VPNv6 SRv6 services through an unchanged-next-hop rustbgpd reflector
to GoBGP 3.37.0. This is one local control-plane run with two prefixes.

The daemon and CLI were built from source
`45f1a44bd0efe18b2ccf87b79855b87a7d839936`, using the repository Dockerfile's
`dev` stage and `ci` profile with four Cargo build jobs. The binaries report
0.68.0; the source SHA identifies the tested development build.
[`images.json`](images.json) records each running image identity, and
[`binaries.sha256`](binaries.sha256) records the daemon and CLI hashes.
The lab used Linux `7.0.0-30-generic` and the configuration in the
[M111 procedure](../../../../tests/interop/m111-srv6-l3vpn-reflection/README.md).

| Property | VPNv4 | VPNv6 |
|----------|-------|-------|
| Inner prefix | `198.51.111.0/24` | `2001:db8:111:1000::/64` |
| Route distinguisher | `65001:111` | `65001:111` |
| Next-hop encoding | 24 bytes: zero RD + IPv6 | 48 bytes: zero RD + global IPv6, zero RD + link-local IPv6 |
| L3 Service endpoint behavior | 19, End.DT4 | 18, End.DT6 |
| Advertised SID value | `2001:db8:111:1::` | `2001:db8:111:1::` |
| SID reconstructed from the transposed label | `2001:db8:111:1:1::` | `2001:db8:111:1:2::` |
| SID structure in bits | 40/24/16/0/16/64 | 40/24/16/0/16/64 |

The [packet oracle result](wire.json) proves byte-identical Prefix-SID values,
VPN NLRI and next hops on the source and reflected links, with only the
expected reflector attributes and Partial-flag handling. Captured OPENs
include the RFC 8950 VPNv4/IPv6-next-hop receive capability. Each direction
contains exactly one OPEN and no NOTIFICATION. Each prefix has one
announcement and one withdrawal per link.

The [FRR allocation view](frr-sids.json) independently matches both
reconstructed SIDs, behaviors, locator and VRF. Live RR and GoBGP snapshots
show VPNv6 withdrawal leaving VPNv4 present, followed by VPNv4 withdrawal.
Both [FRR](source-final-session.json) and [GoBGP](sink-final-session.json)
remain Established. Neither inner prefix appears in either RR kernel route
snapshot. The [driver](driver.log) exited 0 and removed the topology;
capture resources were also removed.

[`m111.pcap`](m111.pcap) retains the packet capture. [`payloads.tsv`](payloads.tsv)
contains the TCP stream, IPv6 endpoints, raw sequence number and payload
export used by the independent Python decoder. From the repository root,
reproduce the decoded result with:

```console
python3 tests/interop/scripts/m111_capture_oracle.py docs/artifacts/interop/m111-srv6-l3vpn-20260906T172814Z/payloads.tsv
```

Both vendor peers are passive and configured before the RR starts. An
earlier development run with active peers failed the strict session check
on an extra startup OPEN; the final configuration removes that race without
relaxing the oracle. This receipt does not claim SID allocation or forwarding
by the RR, EVPN L2 service interoperability, scale, or typed SID rendering.
Malformed-input disposition is covered separately by the wire, MRT and
transport regression tests.
