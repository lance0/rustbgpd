# Pinned-kernel netns calibration

This directory provides the offline-verifiable VM boundary required before a
timing-sensitive Linux netlink receipt can compare kernels. It does not contain
the raw-bridge MAC+IP skew campaign itself and does not change production
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
smoke proves only that the version-pinned privileged netns boundary works. The
later raw-bridge calibration must separately predeclare workload parameters,
timestamp decoded messages on the single `RTNLGRP_NEIGH` stream, run real
ARP/ND under serial and burst profiles, and publish its own bounded
`run.json`/`samples.csv`/`report.json` receipt.

## Offline verification

No QEMU package, image, KVM access, network, Docker daemon, or privilege is
needed for the Stage-A contract suite:

```bash
bash bench/tests/test-netns-calibration-vm.sh
```

The suite destructively proves the closed profile matrix, exact no-network KVM
plan, source lifecycle anchors, guest failure cleanup, provenance binding,
artifact inventory and size limits, sanitation, and final manifest.
