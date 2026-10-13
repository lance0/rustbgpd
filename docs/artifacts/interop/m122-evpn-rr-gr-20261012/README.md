# EVPN route-reflector GR and LLGR receipt

M122 proves EVPN Types 1–5 graceful-restart retention, End-of-RIB stale
sweep, and long-lived graceful-restart marking and expiry with GoBGP 4.10.0.
This is a local correctness receipt from 2026-10-12. The three-node topology
has a restarting source, a rustbgpd route reflector, and an uninterrupted
GoBGP client. EVPN stability classifications and dataplane support boundaries
are unchanged.

## Provenance

The runtime was built from `75a3820a4d245871e5078cecbc2b7e55e6cf87db`, with
the source content hash, uncommitted harness input hashes and both peer binary
hashes retained in
[provenance.json](provenance.json). The source and client run the official
GoBGP 4.10.0 linux/amd64 release binaries, corresponding to source commit
`da824d99912e02124b53741245ee4186c381adcc`.

The original executed harness hashes are preserved. A strengthened offline
oracle replay of the same complete capture additionally checks MP attribute
flags, community flags and complete four-byte values, and the initial source
stream's own ten-route inventory separately from its restart stream. That
replay passes; its oracle hash and test verdict are recorded separately in
`strengthened_oracle_replay`. The local runtime receipt uses the original
dirty harness, while the hosted job exercises the final committed driver and
oracle together.

The retained six phase snapshots also pass the later strengthened driver
checks for each phase's exact stale gauge. That offline snapshot replay and
its driver hash are recorded separately in `strengthened_snapshot_replay`;
the original executed driver hash is preserved.

An ordered wire replay also passes. It assigns each decoded message the
capture row at which the complete TCP prefix through its end was available,
including fragmented and out-of-order segments. Its oracle hash and ordered
witnesses are recorded in `ordered_wire_replay` separately from the original
executed harness hashes.

The final flag-validation replay checks every attribute used as exact wire
evidence: 8, 9, 10, 14, 15, 16 and 22. Its result and new oracle hash are in
`complete_attribute_flags_replay`, preserving all earlier hashes.

A separate live peer admission preceded the new leg. In the M122 topology,
both directions of both sessions were admitted again from captured OPENs:
MP capability 1 contains `00190046` (AFI 25, SAFI 70), GR capability 64
contains the EVPN tuple, and LLGR capability 71 contains the EVPN tuple
with a positive stale time. See [admission.json](admission.json).

## Results

Each Type has a refreshed identity (`s=1`) and an omitted identity (`s=2`).
The RD is `65001:<type><s>`: `65001:11`/`:12` through `65001:51`/`:52`.
All announcements preserve RT `65001:122`, VXLAN encapsulation, and next hop
`10.0.122.2`. Type 1/2/5 announcements carry VNI 10122; Type 3 carries an
ingress-replication PMSI. Type 1 uses EAD per-EVI, with Ethernet Tag 0.

| Phase | RR routes | Client routes | Source stale gauge | Client flaps |
|---|---:|---:|---:|---:|
| Initial, two identities per Type | 10 | 10 | Not yet instantiated | 0 |
| Source SIGKILL, GR retention | 10 | 10 | 10 | 0 |
| Restart and EVPN EoR | 5 | 5 | 0 | 0 |
| Second source SIGKILL, GR retention | 5 | 5 | 5 | 0 |
| LLGR promotion | 5 | 5 | 5 | 0 |
| LLGR expiry | 0 | 0 | 0 | 0 |

The source link stayed down while `gobgpd -r` restarted and the refreshed
five routes were reinjected. Its captured GR capability is
`803c00194680`: the Restart State bit and EVPN forwarding-preserved bit are
set. Its LLGR tuple is `0019468000001e`, advertising 30 seconds for EVPN.
The captured EoR UPDATE body is `00000006800f03001946`: no legacy NLRI and
only an empty MP_UNREACH_NLRI for AFI 25, SAFI 70, after the refreshed five.
The omitted five disappeared from both RR and client.

After the second source loss, all five remaining Types gained `LLGR_STALE`
(65535:6) at the RR and client. The captured reflected announcements carry
the community. Expiry withdraws all five. No client withdrawals occurred
in either GR retention window. The oracle compares full announced NLRI
bytes and complete withdrawal keys; reconstructed withdrawal labels are
zero and are not identity fields. The ordered replay proves the omitted
withdrawals follow the complete source EoR, and survivor withdrawals follow
all five LLGR promotions. No withdrawn identity is later reannounced. Raw
witnesses are in
[wire-witnesses.json](wire-witnesses.json), phase state is in
[state-witnesses.json](state-witnesses.json), and the result is in
[verdict.json](verdict.json).

The source negotiates only EVPN, so its peer-labelled `bgp_gr_stale_routes`
gauge counts these EVPN paths. The gauge is created on the first GR
transition. Subsequent missing metrics or failed queries fail the driver;
they never become zero or route absence. Each later snapshot waits for its
phase's exact gauge value before it is saved. The EVPN route RPC has no
per-route stale flags, so the oracle uses the gauge and exact retained
identities. LLGR is observed through its community. Focused
regressions reject wrong capabilities, zero LLGR time, missing restart
forwarding state or EoR, changed route/RT/next-hop fields, missing LLGR
markers, and failed queries.

## Reproduction

Build `rustbgpd:dev` using the repository's development-image instructions.
Build the pinned peer and capture tools:

```sh
docker build --build-arg TARGETARCH=amd64 --build-arg GOBGP_VERSION=4.10.0 \
  --build-arg GOBGP_SHA256=05a1c9fa1fe5c8d59de5a923efa4afe692c371c33b84750cfeb8f8df24db5fbe \
  -t gobgp:v4.10.0-m122 -f tests/interop/Dockerfile.gobgp-v47 tests/interop
docker build -t rustbgpd:m122-tools -f tests/interop/Dockerfile.m122-tools tests/interop
containerlab deploy -t tests/interop/m122-evpn-gr-rr-gobgp.clab.yml
bash tests/interop/scripts/test-m122-evpn-gr-rr-gobgp.sh
containerlab destroy -t tests/interop/m122-evpn-gr-rr-gobgp.clab.yml
```

The hosted M122 job runs this driver on the checked-out source and joins the
required Interop aggregate. Published evidence includes bounded capability,
EoR, route and provenance witnesses. The original captures and process logs
remain local; unrelated OPEN hostname capabilities are excluded from the
published witnesses.

This receipt covers RR helper behavior for Types 1–5. Type 6, restarting
speaker boot adoption, VTEP forwarding, IRB and multi-homing are outside its
scope. It supplies no throughput, latency, scale or soak result.
