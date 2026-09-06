# Controlled SRv6 L2 reflection

M112 checks one MAC-only EVPN Type2 service form from a controlled raw source,
through a rustbgpd route reflector, to a GoBGP 3.37.0 observer.

Status: the harness and offline negative controls are prepared. The live
scenario has not yet been exercised; no M112 interoperability receipt is
claimed. CI runs the offline Python tests and Bash/ShellCheck checks only.

The fixture uses SRv6 L2 Service TLV6, End.DT2U23, full SID
`2001:db8:112:1:1::`, and SID Structure `40/24/16/0/0/0`. It carries one
16-byte IPv6 next hop and Label1 bytes `00 00 30`: implicit-null in the high
20 bits of the EVPN field (raw label integer 48).
Both the target MAC and a distinct survivor MAC use that service SID. The
route has zero ESI/tag, no host IP, no second label, and no VXLAN community.

The source and GoBGP are passive and ready before the RR initiates either
session. Captures cover both RR links. The test runs these phases:

1. Advertise the target and survivor; require both in the RR and observer.
2. Replace only the target with a malformed SID Structure length. Require
   target withdrawal, continued survivor presence, and established sessions.
3. Re-advertise the valid target and verify both routes and service bytes.
4. Withdraw the target explicitly while retaining the survivor.
5. Withdraw the survivor and verify both route tables are empty.

The packet oracle requires the exact per-route transition history. It checks
each Prefix-SID value, Type2 NLRI, next hop, route target, and expected RR
attributes, including the permitted Prefix-SID Partial flag change. It also
requires one initial OPEN per direction, one TCP session per link, and no
NOTIFICATION. The source's final state and both daemons' session views provide
the final liveness checks. A missing malformed-input withdrawal or temporary
survivor withdrawal fails even if the final table later looks correct.

## Observer boundary

GoBGP's pinned [wire decoder](https://github.com/osrg/gobgp/blob/v3.37.0/pkg/packet/bgp/prefix_sid.go#L114)
recognizes L2 Service TLV6 and its
[server API conversion](https://github.com/osrg/gobgp/blob/v3.37.0/pkg/apiutil/attribute.go#L408)
exposes the received service. Its ordinary CLI reverse conversion rejects
that typed L2 object and can display `attrs: null`. Therefore the driver calls
`ListPath` directly with `enable_only_binary`, using a small
[read-only schema](../configs/gobgp-m112-listpath.proto) matching the pinned
API field numbers. It verifies the returned NLRI and path-attribute bytes,
best-path status, source identity, and each phase's complete route set.

Packet captures remain the wire-preservation evidence: GoBGP's binary output
is a serialization of its stored structures. This fixture deliberately uses
only known TLVs and zero reserved fields. It does not establish unknown or
reserved-byte retention in GoBGP. FRR 10.7.1 skips TLV6 and is not an observer
for this proof.

## Run

Prerequisites are Docker, containerlab, Python 3.11+, grpcurl, jq, and the
existing development, GoBGP, and capture images. The raw source reuses the
capture image's Python; no additional Python packages are required. Commands
run from the repository root and affect only the owned lab namespaces.

The DUT must include SRv6 structural treat-as-withdraw support. By default,
the driver also requires the VPN/EVPN Prefix-SID operator visibility change,
including the matching `rbgp` binary. Build the development image from that
exact source and label its revision. An image label records the build input;
it is not cryptographic source attestation.

```console
revision=$(git rev-parse HEAD)
docker build --target dev --label "org.opencontainers.image.revision=$revision" -t rustbgpd:dev .
docker build -t gobgp:interop -f tests/interop/Dockerfile.gobgp tests/interop
docker build -t bmpsink:m102 -f tests/interop/Dockerfile.bmpsink tests/interop
containerlab deploy -t tests/interop/m112-srv6-l2-reflection.clab.yml
M112_SOURCE_REVISION="$revision" bash tests/interop/scripts/test-m112-srv6-l2-reflection.sh
```

Set `M112_ARTIFACT_DIR` to a new directory to choose the artifact location.
The default includes the UTC start time under `/tmp`. Existing directories
are rejected. The driver checks the exact DUT revision label and GoBGP
version and records container image identities and the harness revision.
Retain the build and driver logs with those artifacts.

For development against a DUT without typed visibility, explicitly set
`M112_REQUIRE_TYPED=0`. The route and wire checks still run, and the receipt
records that typed visibility was not required. Such a run is not the full
M112 visibility proof. If typed fields are present, they must always match
the raw value and expected service structure.

The driver destroys the topology by default. Set `CLEANUP=0` only to retain
it for investigation, then destroy the same topology explicitly. Its owned
capture container and volume are always removed; existing capture resource
names are rejected. Do not run this lab concurrently with CLI doctor tests
or another task that requires no live daemon.

Offline checks require no containers:

```console
python3 tests/interop/scripts/test_m112_capture_oracle.py
bash -n tests/interop/scripts/test-m112-srv6-l2-reflection.sh
shellcheck -x tests/interop/scripts/test-m112-srv6-l2-reflection.sh
grpcurl -import-path tests/interop/configs -proto gobgp-m112-listpath.proto describe apipb.GobgpApi
```

This is a controlled-source reflection and malformed-input proof with an
independent pinned receiver. It is not vendor SRv6 service origination,
complete EVPN-over-SRv6 support, SID eligibility validation, forwarding,
scale, or service convergence evidence. Expectations follow
[RFC 9252 §§3, 6.2.1 and 7](https://www.rfc-editor.org/rfc/rfc9252.html) and
[RFC 8986](https://www.rfc-editor.org/rfc/rfc8986.html).
