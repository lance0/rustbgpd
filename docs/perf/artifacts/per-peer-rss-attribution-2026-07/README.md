# Per-peer RSS attribution receipt artifacts

These are the bounded retained artifacts for
[`per-peer-rss-attribution-2026-07.md`](../../per-peer-rss-attribution-2026-07.md).
The campaign used the real release daemon and the real `reloadstall` BGP client
harness. It first varied peer count and BASE route count independently on
control commit `5c4fdc8f9cf64177af75b47f9afe77f23aca963c`, then measured the
lazy RFC 8654 inbound-buffer candidate
`b40ec3e8b50774c0257166bf06812be84f47df8e` in C/N/N/C order against that
immediate parent.

All generated scenario paths were sanitized to `$RUN`, and generated PIDs to
`$PID`. Host identity and raw DHAT JSON are not retained. Large streams and
lossless DHAT derivatives use deterministic gzip (`gzip -9n`).
`SHA256SUMS` covers every other retained byte.

## Contents

- `runs.tsv` is the compact source table for all release runs. It retains the
  base fleet shape, point-in-time final Adj-RIB-In count, commit, steady and
  peak RSS, in-process jemalloc gauges, and the settled
  update-group/queue/rejection gates.
- `peer-slopes.tsv` recomputes the two fixed-BASE-route peer slopes and the two
  fixed-peer BASE-route slopes from integer mean-cell RSS values under
  continuous churn.
- `owner-deltas.tsv` records the control/candidate DHAT component deltas and
  the exact eager `ReadBuffer::set_max_message_len` owner.
- `runs/<label>/` retains exact commit/tree/shape provenance, preflight,
  process snapshots, status, daemon config check, session/convergence log,
  the 1 Hz RSS stream, and the final Prometheus snapshot. The latter two are
  compressed.
- `dhat/` retains full sanitized derivatives and component tables for the
  10-peer control, 100-peer control, and 100-peer candidate. The derivatives
  are lossless with respect to component, live-at-global-heap-maximum bytes,
  and normalized symbol stack. `dhat/runs/` retains each profiling run's
  provenance, gates, complete final metrics, final process snapshots, and RSS
  stream so its point-in-time final route count remains checkable.
- `host.txt`, `toolchain.txt`, `binaries.sha256`, `commands.txt`, and
  `manifest.json` pin the environment and reproduction contract.

## Recompute

Verify the immutable archive:

```bash
cd docs/perf/artifacts/per-peer-rss-attribution-2026-07
sha256sum -c SHA256SUMS
```

Rebuild each component table from its retained derivative:

```bash
for input in dhat/*.derivative.tsv.gz; do
  output="${input%.derivative.tsv.gz}.recomputed.memory.tsv"
  gzip -cd "$input" |
    python3 ../../../../bench/scale/rebaseline/classify_dhat.py \
      --from-derivative /dev/stdin --output "$output"
done
```

Recompute the fixed-dimension slopes:

```bash
awk -F '\t' '
  NR == 1 { next }
  $1 == "peer" {
    printf "%s\t%.3f KiB/peer\n", $2, ($4 - $3) / ($6 - $5)
  }
  $1 == "base_route" {
    printf "%s\t%.3f B/BASE route\n", $2,
      (($4 - $3) * 1024) / ($6 - $5)
  }
' peer-slopes.tsv
```

The exact driver invocations, in campaign order, are in `commands.txt`. The
harness generates the loopback config and policy fixtures itself; regenerate
those ephemeral files rather than treating them as evidence.

## Interpretation boundary

The C/N/N/C steady-RSS means are 57,141 KiB for the control and 56,956 KiB for
the candidate: −185 KiB (−0.324%). That is below the predeclared 0.645%
same-cell floor, so this archive supports **no RSS improvement claim**.

The release jemalloc point means are 41,214,128 control bytes and 35,345,524
candidate bytes; DHAT live heap is 39,887,660 and 34,150,991 bytes. Those are
raw observations, **not attributable improvement claims**. The harness runs
continuous churn, and the final Adj-RIB-In totals differ: C1/N1/N2/C2 are
10,016/10,000/10,000/10,016, while the DHAT control/candidate are
10,064/10,000. The aggregate allocator and component deltas are therefore
confounded by point-in-time route holdings.

The causal allocation evidence is narrower: the exact 6,150,300-byte
`ReadBuffer::set_max_message_len` eager-reserve stack is present in the control
and absent in the candidate, matching the code path and destructive red proof.
DHAT is a profiling allocator and its byte counts are not resident memory.

The candidate fleet has 100 peers × 100 base routes per peer (10,000 BASE
routes), one homogeneous update group, IPv4 unicast, import-decision explain
disabled, and zero reloads. Convergence means each observer accumulated at
least BASE minus its own base slice in announcements; it is not a unique or
final holdings proof. After that gate, the last 8 stubs each continuously flap
a distinct 16-prefix block every 125ms.

A peer that actually receives a message larger than 4096 bytes still grows its
buffer on demand and retains that high-water allocation for the lifetime of
the session object, including reconnects on that object.
