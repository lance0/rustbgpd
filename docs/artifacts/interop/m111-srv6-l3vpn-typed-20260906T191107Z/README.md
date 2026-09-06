# M111: typed SRv6 L3VPN reflection receipt

This run proves that VPNv4 and VPNv6 SRv6 route views agree with a pinned
FRR advertisement, the reflected wire bytes, and FRR's allocated service SIDs.

The 2026-09-06 run uses FRR 10.7.1 → rustbgpd route reflector → GoBGP 3.37.0.
Both vendor peers are passive and configured before the reflector initiates
either session. The [driver log](driver.log) and [exit status](exit-code.txt)
record a passing run and topology cleanup.

## Identity

- Daemon source: `b8ecd80ec699274bbc86cff95e454b1ec54a4c93`.
- Harness source: `f744f0c615e8b4db8436ab0f3866c6a8c1e75b82`.
- [Image and build identity](build-identity.json), [running images](images.json),
  [binary hashes](binaries.sha256), and [driver identity](identity.json).
- The repository's Docker `dev` target uses the `ci` build profile, with
  `CARGO_BUILD_JOBS=4` added to the build environment. The image carries the
  exact daemon revision label; no daemon source patch was applied.
- [Harness hashes](harness-sha256.txt), [status](harness-status.txt), and
  [diff](harness.diff) record the scripts and configuration used.

The complete workspace gate passed at the daemon revision. The later
`3dc59dd5d43374051edcf160066de972f4722632` integration adds the original M111
proof files without changing daemon source. The harness revision is recorded
separately because it adds the typed-view checks to that original proof.

## Evidence

The [packet capture](m111.pcap), [TCP payloads](payloads.tsv), and independent
[wire oracle result](wire.json) establish byte-identical announced Prefix-SID
values, VPN NLRI, and IPv6 next hops through reflection, expected reflector
attributes, independent withdrawals, and session continuity.

The [typed-view result](typed-visibility.json) compares the retained CLI JSON
with those wire fields and [FRR's allocated SIDs](frr-sids.json). It checks
raw attribute flags and bytes, service type, advertised SID, numeric endpoint
behavior, all six SID Structure fields, labels, RD, next hop, and source peer.
The verifier reconstructs the complete SID from the advertised SID and label;
the CLI reports the advertised values.

| Family | Advertised SID | Label value | Reconstructed service SID | Behavior |
| --- | --- | --- | --- | --- |
| VPNv4 | `2001:db8:111:1::` | 16 | `2001:db8:111:1:1::` | End.DT4 (19) |
| VPNv6 | `2001:db8:111:1::` | 32 | `2001:db8:111:1:2::` | End.DT6 (18) |

Both [initial VPNv4](baseline-vpnv4-rr.json) and
[initial VPNv6](baseline-vpnv6-rr.json) snapshots are retained. The later
[VPNv4 survivor](vpnv4-count-1-rr.json) remains intact after VPNv6 withdrawal;
the final [VPNv4](vpnv4-count-0-rr.json) and
[VPNv6](vpnv6-count-0-rr.json) views are empty. Corresponding GoBGP snapshots
and final session views are retained alongside them. The reflector's kernel
route snapshots contain neither inner service prefix.

## Scope and reproduction

Run the [M111 lab procedure](../../../../tests/interop/m111-srv6-l3vpn-reflection/README.md)
with a fresh artifact directory and a revision-labeled image containing typed
Prefix-SID visibility. This extends the
[earlier wire-only receipt](../m111-srv6-l3vpn-20260906T172814Z/README.md), which
remains unchanged.

This is a two-prefix control-plane and typed-visibility proof. It does not
establish SRv6 forwarding, rustbgpd service origination, scale, or semantic SID eligibility.
The driver log retains initial readiness retries and vendor startup messages;
terminal color escapes are removed and the local checkout path is normalized
to `<repo>`. Packet bytes and query artifacts are unchanged.
