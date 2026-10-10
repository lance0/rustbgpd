# Extracted isolated-retirement controls

This public extraction records the original predeclared plan. It was written
for publication after execution; it does not replace the retained preparation
manifest, actual driver or their original-file hashes in
[retirement-provenance.json](retirement-provenance.json).

- Adjacent source arms: parent `2c55425547bb1fddcb0a4bc30937f26474751020`
  and child `2a5b299ebcfd1659b12ff0f2df7a3aad34954d0b`.
- Unpatched shared policy-stats cell and `reloadstall` instrument from
  `591ac39d4b50fc2c647942713a9ea99c0588a51a`.
- Parent/child/child/parent; seven reloads per process, two processes and
  14 correlated reloads per arm. Default 1,000 peers/400,000 IPv4 prefixes,
  daemon CPUs 2–3, generator 4–5, probes 8–15, 15 s control, 40 s quiescence,
  110 ms read-pair lead, 20 s quiescent offset.
- Seven was chosen before launch instead of the original six-reload proposal:
  the first read pair calibrates the old transition clock and can be outside
  the unchanged −220..0 ms band. Six complete qualifying pairs remain
  necessary in every process. Calibration timing remains included.
- Both exact trees built normally and serially with locked release settings,
  four Cargo jobs and CPUs 40–63. Refresh tracked Rust, protobuf and Cargo
  input timestamps before each build while holding host and shared-target
  locks; verify tracked contents clean and retain input lists/digests/times.
  Copy and hash each daemon/CLI before the next build can replace cache outputs.
- Canonical host lock for the complete ABBA window; original quiet gate
  before every leg. Every native cell criterion must pass. Retain failures
  and stop; do not alter bars or retry automatically to obtain a win.
- Require all seven transitions committed with 1,000 members per leg, all
  native process/leg exits zero, and outer build/ABBA exits zero with a
  window-finish record. The extra attribution-shape check follows the saved
  native leg exit, so the outer stage result is also required.
- Report actor, cohort, prestage/session apply and daemon SIGHUP-received to
  configuration-reload-complete clocks separately, per process and pooled,
  with first versus later reloads. Keep correlated observations separate
  from process repetition; include contrary cases and overlapping ranges.
- The isolated effect belongs to this default-shape parent/child comparison.
  Do not allocate the historical 26-commit S2 interval, add cross-shape
  deltas, or infer completion/CPU gains from the actor timer alone.
- S2/IRR main-versus-release receipt remains preparation only.
