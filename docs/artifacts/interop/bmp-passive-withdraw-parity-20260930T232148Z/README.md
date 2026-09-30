# Passive BMP withdrawal parity receipt

HISTORICAL — bounded local protocol proof completed 2026-09-30 at 23:22:49 UTC.

Two GoBGP 3.37.0 iBGP senders fed a passive rustbgpd instance with an empty
export policy and one raw BMPv3 collector configured for `rib_in_pre` only.
Each sender announced and explicitly withdrew eight distinct IPv4 /32s in
three rounds, with two controlled peer flaps between rounds. The complete
run lasted from 23:21:48 to 23:22:49 UTC, including fresh deployment and cleanup.

| Sender | BGP wire withdrawals | BMP withdrawals | PeerDown | PeerUp |
| --- | --- | --- | --- | --- |
| `10.0.0.2` | 24 | 24 | 2 | 3 |
| `10.0.1.2` | 24 | 24 | 2 | 3 |

The checker required each of the eight intended prefixes to occur exactly
three times on both captures, with the same peer identity. Equal partial
captures cannot pass. PeerDown notifications were counted separately from
RouteMonitoring withdrawals. The BGP capture contained zero exported
announcements. Removing one actual captured BMP withdrawal made the checker
fail with exactly one missing `10.0.0.2` / `198.18.164.1/32` withdrawal.
The runner and cleanup both exited zero; subsequent queries found no owned
containers, networks or capture sidecar.

The [result](result.json) records the counts, exits, source, image and binary
identities. The [evidence archive](evidence.tar.gz) retains the BGP pcapng,
raw BMP JSONL, BGP withdrawal TSV, negative-control output, daemon and driver
logs, harness patch and cleanup evidence. [Checksums](SHA256SUMS) cover both.
Terminal colors were removed from logs and the local checkout path in the
deploy log was replaced with `<harness>`; protocol bytes and counts are unchanged.

The daemon and CLI were built from clean source
`ee99c9321ed969a835e8476898ff95871389fa2f` using the repository Bookworm
builder and the `ci` profile. The only Dockerfile adjustment was builder
parallelism of four. Both fresh binaries were copied into the newly deployed
development container and hashed before daemon startup. This was a component
overlay on the recorded runtime image, not a rebuild of its old image tag.
The harness used that same base plus the archived one-line `resolve_grpc_addr`
fix before `start_rustbgpd`; exact script and configuration hashes are recorded.
The unpatched helper call failed with `No host:port specified`, retained as
`startup-red.log` and its exit status in the archive.

To replay the two captured ledgers from the repository root:

```sh
receipt=docs/artifacts/interop/bmp-passive-withdraw-parity-20260930T232148Z
scratch=$(mktemp -d)
tar -xzf "$receipt/evidence.tar.gz" -C "$scratch"
python3 tests/interop/scripts/check-bmp-passive-withdraw-parity.py   "$scratch/bgp-withdrawals.tsv" "$scratch/bmp.jsonl"
rm -r "$scratch"
```

The runnable [topology](../../../../tests/interop/bmp-passive-withdraw-parity.clab.yml)
and [driver](../../../../tests/interop/scripts/test-bmp-passive-withdraw-parity.sh)
complement M81's Loc-RIB withdrawal assertions with counted pre-policy inputs.
This is a small IPv4 withdrawal-identity and peer-flap proof. It does not prove
full-table memory usage, sustained churn or backpressure behavior, BMP reconnect
completeness, other address families, or production collector performance.
