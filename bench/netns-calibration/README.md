# Pinned-kernel netns calibration

This directory provides the offline-verifiable VM boundary and the
standard-library raw `RTMGRP_NEIGH` decoder required before a timing-sensitive
Linux netlink receipt can compare kernels. It does not change production
behavior.

The ordinary Docker netns harness isolates privileged tests and cleans their
namespaces, but its containers share the host kernel. This runner instead boots
one of two closed, dated Ubuntu cloud-image tuples under QEMU/KVM:

| Profile | Official image | Kernel | iproute2 |
| --- | --- | --- | --- |
| `baseline-jammy-5.15` | Ubuntu 22.04 release 20260826 | `5.15.0-190-generic` | `5.15.0-1ubuntu2.2` |
| `current-noble-6.8` | Ubuntu 24.04 release 20260826 | `6.8.0-138-generic` | `6.1.0-1ubuntu6.4` |

`profiles.json` pins each dated URL, image SHA-256, guest package identity,
QEMU/cloud-image-utils package identity and approved Debian artifact hash, and
the fixed VM shape. The runner checks installed files against dpkg metadata and
executes only the package-owned `/usr/bin/qemu-system-x86_64` and
`/usr/bin/cloud-localds` paths, ignoring same-named commands earlier in
`PATH`. It retains those paths and the actual tool-binary hashes. The verifier also
contains the exact closed tuples, so editing the data file cannot silently add
an arbitrary kernel. The Ubuntu image files are inputs: `run-vm.sh` never
downloads, installs, or updates anything.

## Boundary

Run the host script as the normal user. It requires read/write access to
`/dev/kvm`; it deliberately refuses software emulation and must not be run
through `sudo`. The only elevated context is root inside the disposable guest.
That guest receives no NIC, host home, repository, credentials, or ambient host
environment. It sees only a fresh read-only payload share and a fresh writable
guest-receipt directory.

The QEMU disk is in snapshot mode, so guest writes go to a temporary overlay.
The host verifies the base image before and after the run. A process-group trap
terminates QEMU and removes the seed/payload directory on every exit. The guest
independently creates and deletes one netns containing a VLAN-filtering bridge,
two veth pairs, and VLAN 10/20 membership, then requires the exact pre-run netns
inventory before reporting success.

Before QEMU starts, the runner requires:

- the exact approved image SHA-256 and exact pinned host package versions;
- a clean checkout whose `HEAD` equals `origin/main`;
- the shared nonblocking rustbgpd host lock; and
- two accepted quiet-host samples at least 30 seconds apart.

The output is closed to `request.json`, `host.json`, `plan.json`, `quiet.tsv`,
`console.log`, `guest/guest.json`, `guest/kernel.config`, and a final
`SHA256SUMS`. The verifier rejects missing, extra, symlinked, oversized,
unsanitized, or cross-profile artifacts. The manifest is written only after an
explicit post-VM base-image check; the EXIT trap repeats that check and removes
the manifest on every nonzero outcome, so an unsuccessful run stays unsealed.

## Invocation

After an independent review has authorized a live smoke and the exact image is
already present locally:

```bash
bench/netns-calibration/run-vm.sh \
  baseline-jammy-5.15 \
  /path/to/ubuntu-22.04-server-cloudimg-amd64.img \
  /path/to/fresh-baseline-receipt
```

Repeat with `current-noble-6.8` and its pinned image. A successful environment
smoke proves only that the version-pinned privileged netns boundary works.

The ordinary three-argument invocation and its 300-second timeout remain the
default. The raw-event campaign is a separate explicit mode:

```bash
bench/netns-calibration/run-vm.sh \
  --raw-bridge-skew burst-8 \
  baseline-jammy-5.15 \
  /path/to/ubuntu-22.04-server-cloudimg-amd64.img \
  /path/to/fresh-baseline-campaign-receipt
```

The other campaign profiles are `serial-1` and `burst-32`. Each materializes
an exact 4,000-sample table with the guest's real bridge and port ifindexes
before the first send. Samples are evenly divided across VLANs 10/20 and
IPv4/IPv6. The profiles release one, eight, or 32 UDP sends together; no more
than 32 samples are active. Each batch freezes after completion or five
seconds, and the campaign has a 1,200-second internal wall inside a separate
1,500-second VM timeout. Late events remain diagnostics and cannot change a
frozen sample. After the sender exits, every planned IP in the frozen batch is
idempotently retired, all resulting notifications are drained, and a `nud all`
inventory must prove that zero planned neighbors remain before the next batch.
`raw_bridge_skew.py --plan PROFILE` prints a schema-2 deterministic shape
preview with placeholder ifindexes and null runtime receive-capacity fields,
not an executable receipt.

The campaign has no acceptance threshold. Until an external safe window and
loss rule are predeclared, its output is descriptive and production behavior
remains deferred. No pinned-image campaign is run by the offline suite.

The decoder uses one continuously drained `NETLINK_ROUTE` socket bound to the
`RTMGRP_NEIGH` bitmask 4. A background receive owner timestamps and parses in
socket order while only the foreground mutates pairing state. Before binding,
the collector requests a 4 MiB `SO_RCVBUF`, falls back to
`SO_RCVBUFFORCE` when the ordinary request is capped, and requires the reported
Linux capacity to be at least 8 MiB. Requested/effective capacity, force use,
and the zero planned-neighbor retirement bound are retained in `run.json`.
Receive overflow, truncation, malformed framing, non-kernel events, clock
regression, and ambiguous identity remain fatal, including errors observed
after an apparently complete pair or during synchronized shutdown. IP-neighbor
messages are paired only through the deterministic expected table; they never
infer a VLAN. The `recvmsg` sender must always be the kernel and netlink
sequence must remain zero; Linux's request-correlated `NUD_FAILED` invalidation
may retain the administrator request's port ID in the message header only when
it has no LLADDR. `RTM_DELNEIGH` observations with measured identity and
duplicate or missing sides remain explicit; maintenance deletes without an
LLADDR are strictly parsed but do not change a frozen sample's diagnostics.
The three campaign artifacts are staged in a fresh sibling directory, checked
against a 10 MiB aggregate limit, and atomically published. The outer VM
receipt verifier recomputes the exact plan and report, hard-requires zero
wrong-tenant and ambiguous events, and seals the nested artifacts in the
receipt manifest.

For a disposable parser/pairing proof on the current host kernel, build the
repository's netns test image and run the two-sample smoke. It sends real IPv4
ARP and IPv6 ND traffic across VLANs 10 and 20, requires both FDB/neighbor
pairs, and verifies zero wrong identity, ambiguity, and cleanup residue:

```bash
docker build -t rustbgpd-netns-tests:latest \
  crates/evpn-linux/tests/docker
docker run --rm --network none \
  --cap-add NET_ADMIN --cap-add SYS_ADMIN \
  --security-opt apparmor=unconfined \
  -v "$PWD/bench/netns-calibration/raw_bridge_skew.py:/raw_bridge_skew.py:ro" \
  rustbgpd-netns-tests:latest \
  python3 /raw_bridge_skew.py \
    --current-kernel-smoke --output /tmp/raw-bridge-skew-smoke
```

## Offline verification

No QEMU package, image, KVM access, network, Docker daemon, or privilege is
needed for the Stage-A contract suite:

```bash
bash bench/tests/test-netns-calibration-vm.sh
```

The `scale / receipt checks` CI job runs this exact offline suite and
syntax-checks all three shell surfaces. It does not boot QEMU; the image-pinned
live smoke remains the separately authorized invocation above.

The suite destructively proves the closed profile matrix, exact no-network KVM
plan, source lifecycle anchors, guest failure cleanup, provenance binding,
artifact inventory and size limits, sanitation, and final manifest.
