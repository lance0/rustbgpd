# Revised UPDATE duplicate-table artifacts

This directory retains the compact, sanitized evidence behind
[`../../revised-update-duplicate-table-2026-07.md`](../../revised-update-duplicate-table-2026-07.md).

The two comparison summaries and their 24 compressed logs cover six
counterbalanced same-revision pairs and six counterbalanced
immediate-baseline/candidate pairs. The 24 saved Criterion median-estimate
files are retained because the text logs round values too early to reproduce
the summaries exactly. Six allocation diagnostics retain two baseline repeats,
two candidate repeats, and two final confirmation repeats.

`manifest.json` pins the revisions, trees, Cargo lock, toolchain, CPU, governor,
fixture, and exact acceptance values. `verify.py` recomputes the timing
summaries from the retained estimates, validates all six diagnostic matrices
and negative controls, checks the 24 log streams, and confirms the destructive
proof. `restored-hashset-red.txt` shows the candidate diagnostic going red when
only the allocating `HashSet` implementation is restored.

## Integrity

From this directory:

```console
sha256sum -c SHA256SUMS
find logs -name '*.gz' -print0 | xargs -0 -n1 gzip -t
python3 verify.py
```

`SHA256SUMS` covers every sibling and descendant file except itself. All logs
were compressed with `gzip -n -9`, so their headers contain no source filename
or timestamp. Retained text replaces the measurement root, worktree, and host
identity with placeholders. It contains no username, email, home or temporary
absolute path, PID, credential, runtime address, or tool attribution.

## Interpretation boundary

The allocation result is exact for 10,000 public
`decode_path_attributes_revised` calls on the retained 53-byte, six-attribute
section: one allocation request and 48 requested bytes are removed per call.
The timing result separately measures the production
`UpdateMessage::parse_revised` entrypoint. The encoder and validator diagnostic
rows are unchanged negative controls.

The raw target timing mean is -21.73%, but the same-revision comparison has a
large, one-directional -7.09% head-side bias. Those percentages must not be
subtracted as a formal correction. The defensible result is narrower: every
target attempt is faster, the target and control ranges do not overlap, and
the least-negative target attempt (-19.26%) clears the most-negative control
attempt (-11.15%) by 8.11 percentage points.

No daemon, peer fleet, full table, network, convergence, or RSS was measured.
