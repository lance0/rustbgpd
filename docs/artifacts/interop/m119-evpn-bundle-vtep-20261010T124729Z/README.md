# M119: SR Linux VLAN-aware bundle VTEP receipt

This local run qualifies single-homed VLAN-aware bundle Type 2/3 origination,
SR Linux import, and per-tag forwarding between rustbgpd and Nokia SR Linux
25.10.1-399, using broadcast ARP without static host neighbors or flood rows.

The run passed on 2026-10-10, 12:47:29–12:48:45 UTC: **18 passed, 0 failed**.
All ten directional ping cases delivered three of three echo replies. Deployment,
runner, offline replay and destruction exited zero; all three lab containers
were removed at 12:49:23 UTC. This is a small local qualification, not a hosted
vendor test, scale result or convergence-time measurement. EVPN remains alpha.

## Identity and evidence

[Provenance](provenance.json) records daemon source
`cc56f7c029e02dbd367fa2b443ef35b9d45e8981`, the image source-ID check, immutable
image IDs, binary hashes and individual harness/input hashes. The Rust inputs
were unchanged from that revision; the new harness and documentation are
identified separately by content hashes.

The peer image is pinned to
`ghcr.io/nokia/srlinux:25.10.1@sha256:bc8112667b5a87bee5039ade65b504ac2ef35511210d0675db6c7b0754e8cc4c`.
The runner verifies the deployed image ID and
[reported version/build](srl-version.txt), not just its tag.

- [Run log](run.log): complete qualification output, with ANSI colors removed.
  Transient failed polling observations precede convergence; a phase advances
  only after every predicate passes. The final replay requires all phases.
- [Initial SR Linux RIB](initial/srl-rib.json): decoded EVPN route keys linked
  to their own `attr-id` attribute sets, including next hop, route target,
  VXLAN encapsulation and per-member IMET PMSI.
- [SR Linux bd10 MAC table](initial/srl-bd10.json),
  [bd20 MAC table](initial/srl-bd20.json) and
  [VXLAN destinations](initial/srl-tunnels.json): actual imported MAC and BUM
  destinations with matching member VNIs and no not-programmed reason.
- [Daemon routes](initial/routes.json), [member status](initial/instances.json)
  and [Linux FDB](initial/fdb.txt): per-tag identities, ready instances, zero
  drop snapshots, VLAN-scoped remote MACs and owned IMET flood destinations.
- [Fresh tag-10 forward neighbor cache](forwarding/10-to-2/before-vtep-h10-neighbors.json)
  and [learned cache](forwarding/10-to-2/vtep-h10-neighbors.json): one of ten
  direction/member cases. Every case retains four empty before-caches and both
  dynamically resolved host caches after its ping; static/no-ARP states fail.
- [Remote withdrawal FDB](remote-withdrawn/fdb.txt),
  [local withdrawal RIB](local-withdrawn/srl-rib.json),
  [final FDB](final/fdb.txt), [daemon session](final/peer.json) and
  [SR Linux session](final/srl-peer.json): scoped deletion/restoration and
  session continuity. The complete initial/final FDB inventories are identical.

All JSON, FDB, neighbor, ping and daemon log observations are retained unchanged.
The replay checks 15 state snapshots, all ten ping outputs, 40 empty before-cache
snapshots and each expected learned neighbor. Companion counterexamples reject
wrong/missing attributes, extra routes, crossed tags/VNIs, static flood rows,
unprogrammed vendor destinations and incomplete forwarding evidence.

## Exercised behavior

The [topology](../../../../tests/interop/m119-evpn-bundle-vtep-srlinux.clab.yml)
uses a direct EVPN iBGP session, with rustbgpd VTEP `10.0.119.1` and SR Linux
VTEP `192.0.2.2`. Members share RT `65000:100`; tags 10/20 use VNIs 10010/10020
and distinct RDs. On each side, separate `h10`/`h20` network namespaces use the
same host MAC under both tags. Their IPv4 addresses are `198.18.<tag>.1/24`
and `198.18.<tag>.2/24`. Static access-side MAC entries trigger Type 2
origination; no static host neighbor or zero-MAC flood entry is supplied.

For each Type 2 and IMET, the oracle checks the exact route inventory and
same-path RD, Ethernet Tag, VNI, next hop, shared RT and VXLAN encapsulation.
Type 2 also checks MAC, ESI and IP representation; IMET checks originating
router and ingress-replication PMSI endpoint/VNI. SR Linux's EVPN family view
provides the independent vendor decode; daemon route output and Linux state
establish receive-side programming.

SR Linux's `imported-network-instances` RIB field lists both MAC-VRFs because
both share the RT. It is not used as proof of final tag selection. The oracle
checks the actual bd10/bd20 EVPN MAC destinations and each VXLAN interface's
BUM destination instead. Nokia's
[25.10 VPN Services Guide, section 4.4.5](https://documentation.nokia.com/srlinux/25-10/books/pdf/VPN_Services_Guide_25.10.pdf)
describes the configured Ethernet Tag match at MAC-VRF processing.

With both sides' host caches empty, pings work in both directions for both tags.
Disabling only SR Linux bd10's BGP-EVPN instance withdraws its Type 2 and IMET,
removes only tag 10's received MAC/flood state on rustbgpd, and clears bd10's
EVPN import state. Tag 20 still resolves ARP and forwards in both directions.
Re-enabling bd10 restores both members and all four directional ping cases.
Deleting only rustbgpd's tag-10 access MAC then removes only its Type 2 from
SR Linux: tag 20 and both local IMETs survive. Replacing that MAC restores the
original complete FDB. Both sessions remain established, with zero daemon flaps
or notifications and one unchanged SR Linux establishment count.

This receipt does not qualify tag-scoped multi-homing, IRB on bundle members,
non-zero-tag Type 5, locally assigned VNIs, arbitrary vendor releases, or every
BUM traffic class independently. The unsupported-shape checks remain covered
by [M118](../../../interop.md); no support boundary is widened by this receipt.

## Replay and reproduction

Replay the committed observations without Docker, SR Linux or root privileges:

```sh
python3 tests/interop/scripts/m119_bundle_oracle.py \
  docs/artifacts/interop/m119-evpn-bundle-vtep-20261010T124729Z replay
python3 tests/interop/scripts/test_m119_bundle_oracle.py
```

CI runs both commands. A new live run needs Docker, containerlab, the pinned
SR Linux image and Linux bridge/VXLAN support. From the repository root:

```sh
docker build --target dev -t rustbgpd:m119 .
containerlab deploy -t tests/interop/m119-evpn-bundle-vtep-srlinux.clab.yml
M119_ARTIFACT_DIR=/tmp/m119 \
  bash tests/interop/scripts/test-m119-evpn-bundle-vtep-srlinux.sh
containerlab destroy -t tests/interop/m119-evpn-bundle-vtep-srlinux.clab.yml --cleanup
```

Destroy the topology even if qualification fails. Each live run starts from a
fresh deployment. The historical M82 reflection receipt is unchanged; its
current fixture now uses the same pinned SR Linux image.
