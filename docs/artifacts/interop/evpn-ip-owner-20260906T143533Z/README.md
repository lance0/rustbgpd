# EVPN IP ownership sequence wire proof

HISTORICAL — controlled-peer receipt completed 2026-09-06 at 14:35:33 UTC.

This single isolated run verifies local sequence changes when a different remote
MAC owns an IPv4 or IPv6 binding, while retaining the existing same-ESI checks in
[the runnable peer-sync lab](../../../../tests/interop/peer-sync/README.md).

The runner exited zero, the final BGP session remained established, and all 56
received Type-2 events were reproduced from the retained raw UPDATE bodies. The
DUT process-start sample remained unchanged. Both runner cleanup attempts
succeeded; independent queries subsequently found no owned containers or networks.

| Input or phase | Observed local wire behavior |
| --- | --- |
| Original same-ESI source 3, then 9 | Exact 3 and 9; equal/lower replays stayed quiet |
| Original negative and ownership controls | Wrong RT/tag stayed zero; peer-only MAC never originated; aged host stayed absent |
| Original source withdrawal and cross-shape learning | New children and IP-first downgrade retained 9 |
| Different remote MAC/ESI at 9; IPv4/IPv6, MAC-first/IP-first | All four first local MAC/IP announcements were exactly 10 |
| Remote sequence raised to 19; repeated kernel observations | No local Type-2 changes; all four bindings retained 10 |
| Four new uncontested children | All first announcements were 10; existing children retained 10 |
| Remote withdrawal, then removal of all local IPs | Bindings retained 10; all four MAC-only downgrades first appeared at 10 |
| Remote 19 restored, then fresh local binding activation | All four bindings first reappeared at 20 and remained there through two poll periods |

Duplicate-IP diagnostics were enabled with a 180-second window and threshold 2.
The initial four ownership activations produced four moves and zero threshold
crossings. Repeated observations, uncontested children, withdrawal, and downgrade
left those totals unchanged. Fresh contested reactivation brought the totals to
eight moves and four threshold crossings. Both duplicate-MAC counters remained
zero; absent lazy series are explicitly represented in the result.

The DUT source was clean commit
`af24c995768859c8a8cd7caf443a331ec39a5fbc`; the harness was clean commit
`0cfadda075747694c58333ee5f348a9d27d3e793`. The development image was
`sha256:d770bfc50d1af83fd75b459bb5c75968359fce6a91b9eeda3478e86b9dae93f5`;
the existing Python raw-peer image was
`sha256:dbf9cad241bf0220b24cef681a6f567c46f365b714f66f7ee3d912b2caa70d09`.
The standard Dockerfile had only `ENV CARGO_BUILD_JOBS=4` added to its builder
base for this local build. The archive retains both Dockerfile hashes, the exact
overlay, successful build exit, log, and image inspection. Its OCI source label
records the local build input; it is not cryptographic source attestation.

| File | Evidence |
| --- | --- |
| [peer.json](peer.json) | Sent UPDATE bodies, received BGP bodies, decoded live state and all wire events, command acknowledgements, terminal session |
| [result.json](result.json) | Source/image/harness identity, all phase counter totals, stable process identity, pass and cleanup results |
| [independent-wire-summary.json](independent-wire-summary.json) | Raw UPDATE replay check, four first sequence-10 announcements, final sequence 20 and terminal session |
| [evidence.tar.gz](evidence.tar.gz) | Raw metric scrapes, received-route views, command outputs/exits, daemon logs, independent cleanup queries, and build provenance |
| [SHA256SUMS](SHA256SUMS) | Checksums of the four evidence files above |

The archive preserves protocol bytes, metric scrapes, command exit codes, and
owned-project cleanup evidence. Machine paths in command/build records are
replaced with `<harness>`, `<source>`, `<receipt>`, or `<build-receipt>`; unrelated
host network inventory is explicitly omitted. No protocol or counter values were
changed. The unmodified raw receipts remain the source of these copies.

This is a controlled-source and independent wire-decoder proof of one bounded
local activation behavior. It is not interoperability between independent EVPN
implementations, a churn or scale soak, restart/recovery evidence, complete
simultaneous-move convergence, stale-entry handling, or full RFC 9721 conformance.
