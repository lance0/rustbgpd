# M120: SR Linux bundle-member interface-less IRB receipt

This local run qualifies single-homed VLAN-aware bundle members bound to an
interface-less IP-VRF against Nokia SR Linux 25.10.1-399, with operator-provisioned
SVIs, VRF attachments and L3 VXLAN devices.

The run passed on 2026-10-11, 04:58:52–05:00:39 UTC: **37 passed, 0 failed**.
EVPN and Linux dataplane behavior remain alpha. This small local topology does
not establish hosted vendor qualification, scale or convergence-time results.

## Identity and evidence

[Result and provenance](result.json) distinguish image build commit
`1d3d6b56ca5f815d8ba1b342d2effb98399f15fd` from execution commit
`f3bbe73378faee7112016e868d3837048c4ad2b4`. Both have Rust source-ID
`d708f51f0ee913fc03ce742f7e3248177c08168d5ae9d6b32f66c1f51e500c59`;
intervening changes affect the lab fixtures and capture completion. The runner
checked immutable image IDs, deployed daemon hashes, source identity and the
vendor's reported version/build. The exact harness input hashes are recorded.

SR Linux is pinned to
`ghcr.io/nokia/srlinux:25.10.1@sha256:bc8112667b5a87bee5039ade65b504ac2ef35511210d0675db6c7b0754e8cc4c`.
The [evidence archive](evidence.tar.gz) retains all 192 state and driver files
unchanged, including eight daemon/vendor/kernel snapshots, positive and negative
ping outputs, empty before-probe neighbor tables, the routed PCAP, capture
witness, effective configurations and daemon log. Its `raw-sha256.json` checks
each original file. The archive includes exactly the run's 191 `state/` files
and `driver.log`; host preflight, deployment and orchestration logs and earlier
attempts are outside this selection. [Checksums](SHA256SUMS) cover the archive
and result.

Deployment, driver and cleanup exited zero. All owned containers and the exact
management network were absent afterward; recorded process identities were
reaped. The raw driver log retains transient polling failures before a phase
converges, ANSI colors and UTC-04 clock times.

## Exercised behavior

The [topology](../../../../tests/interop/m120-evpn-bundle-irb-srlinux.clab.yml)
uses tags 10/20, L2VNIs 10010/10020 and shared L2 RT `65000:100`. The separate
IP-VRF uses L3VNI 50120 and RT `65000:50120`. Interface-less Type 5 routes carry
ESI zero, Ethernet Tag zero, gateway zero and the advertising VTEP's Router MAC;
member Type 2/3 routes retain their tag and L2VNI.

The oracle checks exact daemon and SR Linux route inventories with attributes
from each route's own attribute set, imported vendor routes and MAC destinations,
Linux routes across all tables, neighbors and the complete FDB. Twenty-five
successful three-request ping cases start with empty host neighbor tables. A
captured routed probe to `198.19.120.2` selects its Type 5 host route: all three
requests carry L3VNI 50120 and SR Linux's advertised inner Router MAC.

Export policy withdraws only `198.19.120.0/24` and `198.19.120.2/32`. The Type 5
inventory changes from ten to eight, and installed remote prefixes from four to
two; the withdrawn destination loses all three probes. Both L2 members and the
other remote prefix remain reachable. Removing the policy restores the original
inventories and bidirectional routed forwarding. The SR Linux fixture explicitly
preserves the tenant RT on accepted exports and excludes its two IRB gateway
host routes while this policy is attached.

An unsupported `gateway_ip` reload is rejected without advancing the committed
generation. Unlinking one member from the IP-VRF and relinking it each advance
one generation while retaining both L2 identities. Final routed probes pass,
the complete initial/final EVPN RIB and FDB match, and both peers retain their
session without a flap.

This receipt does not qualify bundle multi-homing, locally assigned VNIs,
non-zero-tag Type 5, GW-IP/ESI recursion through bundle members, Type 2 symmetric
host routing, arbitrary vendor versions or the v1 stable surface.

## Replay and reproduction

Replay the eight state snapshots and capture-completion witness without Docker
or root privileges from the repository root:

```sh
receipt=docs/artifacts/interop/m120-evpn-bundle-irb-20261011T045852Z
scratch=$(mktemp -d)
tar -xzf "$receipt/evidence.tar.gz" -C "$scratch"
python3 tests/interop/scripts/m120_bundle_irb_oracle.py "$scratch/state" replay
python3 tests/interop/scripts/m120_bundle_irb_oracle.py "$scratch/state" capture-witness
rm -r "$scratch"
```

The live [driver](../../../../tests/interop/scripts/test-m120-evpn-bundle-irb-srlinux.sh)
also checks ping results, route lookup and the final PCAP. A fresh run needs
Docker, containerlab, the pinned vendor image and Linux bridge/VXLAN support:

```sh
docker build --target dev -t rustbgpd:m120 .
docker build -f tests/interop/Dockerfile.bmpsink -t bmpsink:m120 tests/interop
containerlab deploy -t tests/interop/m120-evpn-bundle-irb-srlinux.clab.yml
M120_ARTIFACT_DIR=/tmp/m120 bash tests/interop/scripts/test-m120-evpn-bundle-irb-srlinux.sh
containerlab destroy -t tests/interop/m120-evpn-bundle-irb-srlinux.clab.yml --cleanup
```

Always destroy the topology after a run, including a failed run. A new native
qualification must use a fresh deployment and images matching its Rust source.
