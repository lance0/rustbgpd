# M111: valid SRv6 VPN reflection with semantic eligibility

This rerun confirms that valid transposed VPNv4 and VPNv6 SRv6 services remain
selected, visible and reflected after semantic SID eligibility is enforced.

The local run passed on 2026-09-06 at 20:04 UTC using FRR 10.7.1 through
rustbgpd to GoBGP 3.37.0. The unchanged
[M111 procedure](../../../../tests/interop/m111-srv6-l3vpn-reflection/README.md)
passed its wire and typed-view oracles, independent withdrawals, and final
session checks. The [driver log](driver.log) and [exit status](exit-code.txt)
record completion and cleanup.

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

## Evidence

The [capture](m111.pcap), [TCP payloads](payloads.tsv), and
[wire result](wire.json) prove exact announced Prefix-SID, VPN NLRI and IPv6
next-hop preservation, expected reflector additions, independent withdrawals,
and session continuity.

The [typed-view result](typed-visibility.json) checks raw bytes and flags,
service type, advertised SID, numeric behavior, all SID Structure fields,
labels, RD, next hop and source peer against wire evidence and
[FRR's allocated SIDs](frr-sids.json). The verifier reconstructs each complete
SID from the advertised SID and label; the CLI exposes advertised values.

| Family | Advertised SID | Label value | Reconstructed SID | Behavior |
| --- | --- | --- | --- | --- |
| VPNv4 | `2001:db8:111:1::` | 16 | `2001:db8:111:1:1::` | End.DT4 (19) |
| VPNv6 | `2001:db8:111:1::` | 32 | `2001:db8:111:1:2::` | End.DT6 (18) |

Both [initial VPNv4](baseline-vpnv4-rr.json) and
[initial VPNv6](baseline-vpnv6-rr.json) routes are present. The later
[VPNv4 survivor](vpnv4-count-1-rr.json) remains after VPNv6 withdrawal. Both
final route views are empty, and both peers remain established. The stored
kernel route snapshots contain neither inner service prefix.

CI replays the wire and typed results without containers. The earlier
[wire-only](../m111-srv6-l3vpn-20260906T172814Z/README.md) and
[typed-view](../m111-srv6-l3vpn-typed-20260906T191107Z/README.md) receipts remain
unchanged. The companion
[M112 receipt](../m112-srv6-semantic-20260906T200333Z/README.md) exercises an
invalid EVPN SID Structure replacement on this same daemon build.

This is positive compatibility evidence for two valid VPN service routes;
it does not exercise invalid VPN SIDs or establish full semantic-rule
coverage, SRv6 forwarding, rustbgpd service origination, scale or convergence
bounds. Generated packet and query artifacts are unchanged. Only the driver
log had terminal color escapes removed and the local checkout path normalized
to `<repo>`; readiness retries and vendor startup messages remain recorded.
