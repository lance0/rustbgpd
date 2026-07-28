# Policy attribution Criterion evidence

This directory retains the smallest privacy-safe package needed to reproduce
and audit the policy-attribution result. Raw Criterion trees and command logs
remain outside the repository because they contain absolute paths and host
identifiers.

- `attempt-estimates.tsv`: median point estimates and derived deltas for every
  side of all six alternating attempts.
- `control-summary.md`, `isolated-summary.md`: sanitized runner summaries.
- `metadata.txt`: sanitized refs, host class, pinning, governor, and toolchain.
- `commands.txt`: exact invocations.
- `manifest.json`: machine-readable contract and row classifications.
- `verify.py`: fail-closed structural and claim verifier.
- `red-proofs.md`: independent verifier mutations and their failures.
- `verification.txt`: clean verifier and checksum output.
- `SHA256SUMS`: retained-file integrity.

Run from this directory:

```console
python3 verify.py
sha256sum -c SHA256SUMS
```
