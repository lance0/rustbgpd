# Retained artifact

This directory retains the sanitized control and A/B summaries and metadata,
plus every exact Criterion median estimate used by the gate. Raw command,
compiler, and benchmark logs are intentionally excluded.

Run from the repository root:

```text
python3 docs/perf/artifacts/private-single-best-fanout-2026-07/verify.py
(cd docs/perf/artifacts/private-single-best-fanout-2026-07 && sha256sum -c SHA256SUMS)
```

The verifier checks source identity, checksums, archive determinism, exact scan
counts, all six per-row attempts, the accepted 8/64/256 gate, and the scaling
bound. The one-peer result is unclaimed. No daemon, convergence, network, or
full-table result is claimed.
