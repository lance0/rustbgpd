# SRv6 L3VPN reflection with FRR

M111 checks VPNv4 and VPNv6 SRv6 service advertisements from FRR 10.7.1 through
a rustbgpd route reflector to a GoBGP 3.37.0 observer.

The source allocates service SIDs beneath `2001:db8:111:1::/64`, with a
40-bit block, 24-bit node and 16-bit function. Its function bits are transposed
into the VPN label field. The reflector preserves the source next hop and
service bytes; it allocates no SIDs and installs neither inner prefix into
its kernel routing tables.

The [2026-09-06 receipt](../../../docs/artifacts/interop/m111-srv6-l3vpn-20260906T172814Z/README.md)
records the passing local run, exact development source and image identities,
packet capture, and FRR SID allocation checks. Both vendor peers are passive
and configured before the RR starts, avoiding competing startup connections.
The later [typed-visibility receipt](../../../docs/artifacts/interop/m111-srv6-l3vpn-typed-20260906T191107Z/README.md)
also checks the CLI's raw and typed service fields against the captured
advertisement and FRR allocation.

Run from the repository root after building the interop images:

```console
revision=$(git rev-parse HEAD)
docker build --target dev --label "org.opencontainers.image.revision=$revision" -t rustbgpd:dev .
docker build -t gobgp:interop -f tests/interop/Dockerfile.gobgp tests/interop
docker build -t bmpsink:m102 -f tests/interop/Dockerfile.bmpsink tests/interop
containerlab deploy -t tests/interop/m111-srv6-l3vpn-reflection.clab.yml
M111_SOURCE_REVISION="$revision" bash tests/interop/scripts/test-m111-srv6-l3vpn-reflection.sh
```

The current driver requires a DUT and matching `rbgp` binary with typed
Prefix-SID visibility. `M111_SOURCE_REVISION` must be the full commit SHA in
the DUT image's revision label. The label records the build input; it is not
cryptographic source attestation. The driver records both DUT and harness
revisions, harness hashes, and any uncommitted harness changes.

Set `M111_ARTIFACT_DIR` to choose a new output directory; the default is a
UTC-timestamped directory under `/tmp`. Existing directories are rejected,
preserving earlier receipts. The driver destroys its topology by default;
set `CLEANUP=0` to retain it for investigation, then use `containerlab destroy`
with the same topology file. Capture containers and volumes created by the driver
are always removed.

The packet oracle independently reassembles both TCP sessions and checks:

- One OPEN per direction and no NOTIFICATION or additional BGP session.
- Both VPN families, their route distinguisher and exact inner prefixes.
- IPv6 VPN next hops, the L3 Service TLV, SID Information and SID Structure,
  endpoint behavior, and reconstructed transposed SID.
- Byte-identical Prefix-SID values, VPN NLRI and next hops through reflection,
  with only the expected reflector attributes and unknown-attribute Partial
  flag change.
- An announcement followed by a withdrawal for each family. Live queries
  additionally prove that withdrawing VPNv6 leaves VPNv4 present and both
  sessions remain Established after the final withdrawal.

The artifacts include PCAP, decoded payload rows, image and version identities,
source configuration and SID allocation views, RR and observer route snapshots,
kernel route snapshots, final session views, and the packet-oracle result.
The original receipt establishes control-plane reflection for this topology.
It does not prove SRv6 forwarding, EVPN L2 services, scale, or SID-aware
operator rendering.

The current driver additionally retains both initial typed VPN snapshots and
the VPNv4 survivor snapshot. Its typed verifier compares raw Prefix-SID bytes,
SID values, endpoint behavior, SID Structure, labels, route identity and next
hop with `wire.json`, reconstructs each allocated SID from the typed view and
label, and checks FRR's SID allocation. It then checks both withdrawn views.
The typed-visibility receipt records the passing rerun. A separate
[semantic-eligibility rerun](../../../docs/artifacts/interop/m111-srv6-eligibility-20260906T200426Z/README.md)
confirms these valid transposed services remain reflected and visible with
semantic SID eligibility enabled. CI replays its wire
and typed results without containers; the original dated receipt above
remains evidence for its original wire scope.

Run the offline oracle regressions without a lab:

```console
python3 tests/interop/scripts/test_m111_capture_oracle.py
python3 tests/interop/scripts/test_m111_typed_visibility.py
```

Wire expectations follow [RFC 9252](https://www.rfc-editor.org/rfc/rfc9252.html),
[RFC 8950](https://www.rfc-editor.org/rfc/rfc8950.html), and
[RFC 8277](https://www.rfc-editor.org/rfc/rfc8277.html). Reserved label bits are
preserved but ignored when interpreting the advertised label field.
