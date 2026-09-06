# Same-ESI sequence adoption wire proof

This isolated lab checks exact local Type-2 sequence adoption with a controlled
BGP source and independent wire receiver. It is not interoperability evidence
between two independent EVPN implementations, a performance benchmark, or a churn
soak.

The DUT uses the existing Gate 8b bridge, VXLAN, and CE veth setup. Its peer sends
same-ESI, matching-RT, Ethernet-tag-zero routes at sequence 3 before local hosts
are learned, then raises the sequence directly to 9. The receiver checks the
DUT's own RD, ESI, MAC, IP, tag, VNI, next hop, route target, and MAC Mobility
community. It requires fresh exports at exactly 3 and 9, rejects transient 4/10
exports, and checks that equal/lower replays produce no local Type-2 changes over
two originator poll periods. The topology fixes the encapsulation to VXLAN. In
accordance with RFC 8365 sections 5.1.3 and 6, absent Encapsulation communities use
that local profile; a present community must identify VXLAN. This proof does not
validate automatic encapsulation discovery between different implementations.

The cases include a MAC-only local host, local IPv4 and IPv6 children synchronized
from a MAC-only peer route, and children synchronized from a MAC/IP peer route.
A peer-only MAC shares another local host's IPs but must never acquire local
ownership. Wrong-RT and nonzero-tag controls must retain local sequence zero.
Removing one local host and replaying its remote route must not resurrect it.
The peer also withdraws its routes while keeping BGP established. A successful
received-route positive control and empty complete page establish that boundary.
After two originator polls, new IPv4/IPv6 children must inherit the retained MAC
sequence 9; removing the last IP from an IP-first host must create MAC-only at
sequence 9. Wire history proves that host had no earlier MAC-only advertisement.

All four duplicate-MAC/IP counter families are summed across every label set.
A missing lazy counter is recorded explicitly as `present: false`, `series: 0`,
`total: 0`; an unsuccessful scrape, malformed value, or missing process sample
fails. A changed process-start sample also fails. Duplicate-IP diagnostics are
enabled; duplicate-MAC detection retains its default detect-only action.

Run from a clean checkout containing the runtime behavior being tested. Build the
standard development image with an exact source label, and prepare the existing
Python-equipped raw-peer image if it is not already available:

```sh
proof_revision=$(git rev-parse HEAD)
docker build --target dev \
  --label "org.opencontainers.image.revision=$proof_revision" \
  -t rustbgpd:peer-sync-proof .
docker build -f tests/interop/Dockerfile.bmpsink -t bmpsink:m102 tests/interop
python3 tests/interop/scripts/run-evpn-peer-sync-proof.py \
  --image rustbgpd:peer-sync-proof --source-revision "$proof_revision" \
  --raw-image bmpsink:m102 --output /tmp/evpn-peer-sync-proof
```

The output directory must not exist. The runner rejects a mismatched DUT source
label, resolves both images to immutable local IDs, records image IDs/digests and
source/harness revisions, and uses `--pull never`. A build label is a local build
receipt, not cryptographic source attestation. Keep the build log with the run.
When using a separately built DUT image, pass its actual source revision rather
than the harness checkout revision.

Docker Compose and Linux bridge/VXLAN support are required. The DUT is privileged
inside its owned container, with no host network namespace or host socket mount.
The runner rejects an existing Docker network overlapping `10.99.0.0/24`, starts
a unique Compose project, and applies neighbor-lifetime settings only inside the
DUT container. Allow about two minutes for the single attempt. Run it separately
from tests that require an idle host or no running daemon.

Every command's output and exit status, source UPDATE bytes, received BGP message
bodies, decoded wire events, raw metric scrapes, daemon logs, and the final result
are retained in the receipt directory. A fresh run ID, command acknowledgements,
and peer heartbeat prevent a previous capture from satisfying a new phase. The
runner always attempts project teardown twice and checks for remaining owned
containers/networks; it never removes another project's resources. If teardown
fails, the result fails and names the unique project for manual cleanup. Preserve
failed setup receipts as well as successful runs.

Offline oracle and orchestration-contract checks require only Python:

```sh
python3 tests/interop/scripts/test_evpn_peer_sync_oracle.py
```

A fresh Gate 8b churn run is separate evidence. Record its actual duration, source,
images, restart epochs, raw metrics, and terminal recovery. A short FDB churn run
does not establish long-term memory stability or MAC/IP churn behavior. Dated soak
receipts and their missing metric samples remain unchanged.
