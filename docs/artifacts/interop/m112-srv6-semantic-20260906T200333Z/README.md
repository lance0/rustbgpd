# M112: retained invalid SRv6 SID and reflection recovery

This run proves that a structurally valid but semantically invalid SRv6 L2
replacement remains visible on the reflector while its target route is
withdrawn from an independent GoBGP 3.37.0 observer.

The local run passed on 2026-09-06 at 20:03 UTC using the optional semantic
control in the [M112 procedure](../../../../tests/interop/m112-srv6-l2-reflection/README.md).
All seven phases and the independent packet oracle passed. The
[driver log](driver.log) and [exit status](exit-code.txt) record completion
and cleanup. This is a two-MAC, single-service control-plane proof.

## Build identity

- Daemon source: `cdbf7ebd5d12ac07434b3ae99dd693784f1164c9`.
- Harness source: `8a25407617dbef3b46e9285783b1718a0b0b7e8a`.
- Image: `sha256:90b671563eec8e9ef999aba14bb3c758cfe41dec4509cc12b902ed12a21d9e07`.
- [Build identity](build-identity.json), [running images](images.json),
  [binary hashes](binaries.sha256), and [driver identity](identity.json)
  record the exact development build.
- The repository Docker `dev` target used the `ci` profile. The only Dockerfile
  adjustment was `ENV CARGO_BUILD_JOBS=2`; no daemon source patch was applied.
  The revision label records the build input, not cryptographic source attestation.
- [Harness hashes](harness-sha256.txt), [status](harness-status.txt), and
  [diff](harness.diff) record the clean scripts and configuration used.

## Semantic replacement and recovery

The target is MAC `02:00:00:00:01:12`, RD `10.112.0.2:112`, with full SID
`2001:db8:112:1:1::`, L2 Service TLV6 and End.DT2U (23). The source changes
only the SID Structure locator-block length from 40 to 100. The six fields
become `100/24/16/0/0/0`, totaling 140 bits, while every TLV length remains
correct. The source record retains the exact
[replacement bytes](semantic_invalid-source.json).

| View during the invalid replacement | Required and observed result |
| --- | --- |
| [Installed-best RR view](semantic_invalid-rr.json) | Target absent; survivor present with original attributes |
| [Received RR page](semantic_invalid-received.json) | Both routes retained; target has exact invalid raw bytes and typed structure, with no decode error |
| [Exact-key explain](semantic_invalid-explain.json) | One retained candidate, no installed or selected best, selection reason `srv6_sid_invalid` |
| Export in the same explain | No staged or committed target; `srv6_service` stop gate with code `srv6_sid_invalid` |
| [GoBGP binary view](semantic_invalid-observer.json) | Target absent; survivor retains the original NLRI and service bytes |

The export decision is `no_best_route`, because that gate stops before the
additional SRv6 gate. The semantic reason remains visible in selection and
the gate list. The route is retained as an accepted candidate; this case
is separate from structural treat-as-withdraw.

The corrected replacement restores the original `40/24/16/0/0/0` bytes.
[Received](semantic_recovery-received.json), [explain](semantic_recovery-explain.json),
[installed-best](semantic_recovery-rr.json), and
[observer](semantic_recovery-observer.json) snapshots confirm recovery, with
the target selected and advertised again.

## Packet and session evidence

The [packet capture](m112.pcap), [TCP payloads](payloads.tsv), and
[wire result](wire.json) require these exact target histories:

- Source: announce, malformed replacement, announce, semantic-invalid
  replacement, announce, explicit withdrawal.
- Reflected: announce, withdraw, announce, withdraw, announce, withdraw.

The survivor has only its initial announcement and final withdrawal; any
intermediate churn fails. Announcements preserve exact NLRI, IPv6 next hop,
Prefix-SID and expected RR attributes. Withdrawals match the RD/tag/MAC/IP
route key, with raw labels and ESI recorded separately. Every captured
direction has one initial OPEN and no NOTIFICATION, and each link has one
TCP session. Final [RR](rr-final-sessions.json),
[observer](sink-final-session.json), and [source](source-final.json) views
remain established.

The original baseline, malformed replacement, recovery, target withdrawal,
and survivor cleanup still run. The earlier
[five-phase receipt](../m112-srv6-l2-20260906T192025Z/README.md) is unchanged
and retains byte-identical offline replay output.

## Replay and boundaries

CI replays `wire.json` with `--semantic-control`, all seven RR/observer
phase pairs, and both received/explain pairs. Offline mutation controls
reject missing retention or reasons, bad typed/raw bytes, target leakage,
missing withdrawals, survivor churn, and incomplete recovery.

This proves one invalid SID Structure replacement and recovery for MAC-only
Type 2. It does not establish complete semantic-rule coverage, vendor SRv6
origination, other EVPN forms, forwarding, scale, or convergence bounds.
The [companion M111 rerun](../m111-srv6-eligibility-20260906T200426Z/README.md)
checks valid transposed VPNv4/VPNv6 services on the same daemon build.

Generated packet and query artifacts were copied unchanged. Only the driver
log had terminal color escapes removed and the local checkout path normalized
to `<repo>`; its initial source-readiness retry remains recorded.
