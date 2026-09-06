# M112: controlled SRv6 L2 reflection receipt

This run proves MAC-only EVPN Type 2 reflection and typed SRv6 visibility,
including malformed replacement withdrawal and recovery, from a controlled
raw source through rustbgpd to a GoBGP 3.37.0 observer.

The local run passed on 2026-09-06 at 19:20 UTC. All five phases and the
independent packet oracle passed; the [driver log](driver.log) and
[exit status](exit-code.txt) record completion and cleanup. This is one small
control-plane run with two MACs, using one SRv6 service form.

## Identity and service

- Daemon source: `b8ecd80ec699274bbc86cff95e454b1ec54a4c93`.
- Harness source: `10abb3dd76466dbdbd12090cabeac0c18d4b09d5`.
- [Build identity](build-identity.json), [running images](images.json),
  [capture image](capture-image.json), [binary hashes](binaries.sha256), and
  [driver identity](identity.json) identify the exact development build.
- The Docker `dev` target uses the `ci` build profile with four Cargo build
  jobs. The daemon image carries its source revision label; the daemon and
  CLI report 0.68.0. The label records the build input, not source attestation.
- [Harness hashes](harness-sha256.txt), [status](harness-status.txt), and
  [diff](harness.diff) record the unmodified scripts and configuration used.

| Field | Value |
| --- | --- |
| Route distinguisher | `10.112.0.2:112` |
| Target MAC | `02:00:00:00:01:12` |
| Survivor MAC | `02:00:00:00:02:12` |
| Next hop | `2001:db8:112:10::2` (16-byte IPv6) |
| Service | L2 Service TLV6, End.DT2U (23) |
| Advertised full SID | `2001:db8:112:1:1::` |
| SID Structure | 40/24/16/0/0/0; no transposition |
| Announced Label1 bytes | `00 00 30`; implicit-null in the high 20 bits |
| CLI label value | 48, the raw 24-bit EVPN field |

Both routes have zero ESI and Ethernet tag, no host IP, and no second label
or VXLAN community. The raw source and observer are passive and ready before
the reflector initiates either session.

## Evidence

The [packet capture](m112.pcap), [TCP payloads](payloads.tsv), and
[wire result](wire.json) prove exact announced NLRI, IPv6 next hop and
Prefix-SID values through reflection, with the expected ORIGINATOR_ID,
CLUSTER_LIST and permitted Prefix-SID Partial flag. Every captured direction
has one initial OPEN and no NOTIFICATION; each link has one TCP session.

| Phase | Target | Survivor | RR / observer snapshots |
| --- | --- | --- | --- |
| Baseline | Present | Present | [RR](baseline-rr.json), [observer](baseline-observer.json) |
| Malformed replacement | Withdrawn | Present | [RR](malformed-rr.json), [observer](malformed-observer.json) |
| Recovery | Present | Present | [RR](recovery-rr.json), [observer](recovery-observer.json) |
| Explicit target withdrawal | Withdrawn | Present | [RR](withdraw-rr.json), [observer](withdraw-observer.json) |
| Survivor cleanup | Absent | Absent | [RR](cleanup-rr.json), [observer](cleanup-observer.json) |

The malformed source changes only the SID Structure's declared length from
six to seven with six value bytes present. The [source record](malformed-source.json)
retains those bytes. The [daemon log](rustbgpd.log) reports treat-as-withdraw,
and the packet history requires a target withdrawal before recovery. The
survivor has only its initial announcement and final withdrawal; a temporary
withdrawal would fail the oracle.

Each nonempty RR snapshot has matching raw Prefix-SID bytes and typed TLV6,
full SID, behavior 23 and all six Structure fields. The empty cleanup result
reports no typed route to inspect. GoBGP snapshots use its binary `ListPath`
API because the pinned CLI reverse conversion cannot render this typed L2
service. Their retained NLRI and attributes match the fixture, including
best-path and source identity checks. Packet bytes provide the independent
preservation evidence. The [RR](rr-final-sessions.json),
[observer](sink-final-session.json) and [source](source-final.json) all remain
established after the final withdrawal.

## Withdrawal identity and earlier oracle failure

An earlier run at 19:14 UTC passed every live phase but failed the packet
oracle because it incorrectly required withdrawn Label1 bytes to equal the
advertised service label. The reflector reconstructs withdrawals from the
route key and emits `00 00 00`; announced labels remained `00 00 30`.

[RFC 7432 §7.2](https://www.rfc-editor.org/rfc/rfc7432.html#section-7.2)
excludes ESI and labels from the Type 2 route key. The corrected oracle keeps
announcement byte checks unchanged and checks withdrawal shape plus RD,
Ethernet tag, MAC and IP identity. Negative controls reject changed route
keys and changed announcement labels. The wire result records both explicit
source withdrawals with label `000030` and all three reflected withdrawals
with label `000000`, together with their raw ESI bytes.

The earlier failed capture and logs remain local and unchanged. Replaying
that capture with the corrected oracle passed, and this separate fresh run
passed the complete driver. No daemon change was needed for the correction.

## Scope and reproduction

Follow the [M112 procedure](../../../../tests/interop/m112-srv6-l2-reflection/README.md)
with a fresh artifact directory and matching revision-labeled daemon/CLI
image. CI replays the committed wire and route snapshots without containers.

This is controlled-source reflection with one independent pinned receiver.
It does not establish vendor SRv6 service origination, complete EVPN-over-SRv6
support, forwarding, SID eligibility, scale, or convergence bounds. Reserved
and unknown-field retention is outside this fixture.

All generated artifacts were copied without modification. The separately
retained driver log removes terminal color escapes and normalizes the local
checkout path to `<repo>`; packet and query bytes are unchanged.
