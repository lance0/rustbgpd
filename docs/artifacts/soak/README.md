# Soak evidence artifacts

Frozen run evidence for the long-running soak and scale gates: per-run
`soak.log`, `run.json`/`report.json` summaries, and `samples.csv` time
series. Each directory is a single run, named `<gate>-<UTC-timestamp>`.

## Normalization note

Host-specific absolute paths were normalized before publication;
measurements and command output are otherwise unchanged. Absolute run
paths that embedded a host home directory were rewritten to the
`<SOAK_HOME>` placeholder — only the path prefix was substituted, and no
sample value, threshold, timing, or verdict was altered.
