# Mixed export-policy reload receipt

This directory retains the corrected integrated comparison for a mixed
route-server policy reload: 700 real BGP sessions, 400,400 routes, 600 peers
whose export policy changes, 100 content-stable peers, four alternating reloads,
and a 30-second control window. The base is
`a170ab0f38fd97cc294d56ba5f283c7221c2c166`; the frozen candidate is
`fa2759e9b19ecbc00f245c6d07e520e8f28e0882`. The candidate harness from the
same frozen SHA drove both daemons. Runs were serial and did not overlap.

The result is deliberately reported as mixed. Across the four reloads, the
median completion p50 fell from 220.148412 s to 1.894807 s, a 116.185x
improvement. The median completion maximum fell from 436.698156 s to 2.925734
s, a 149.261x improvement. However, the median full-fleet delivery-gap p50 rose
from 976.8845 ms to 2022.590 ms (2.070x), and the median full-fleet maximum rose
from 1002.756 ms to 2906.551 ms (2.899x). The cohort transaction therefore
fixes reload completion scaling, but does not satisfy the earlier sub-second
delivery-stall goal. Chunking member resync remains required; this receipt is
not an unconditional performance acceptance.

Every recorded cycle kept 700/700 sessions up, produced fresh post-completion
`stable-out` evidence from 100/100 stable peers, and recorded zero UPDATE parse
errors. Those fields are part of every row in
`mixed-policy-reload-600-changed-100-unchanged.csv`; a row is not emitted unless
the harness checks pass. This is the corrected unique-generation completion
contract, not the withdrawn historical completion heuristic.

## Operation shape

The base drove 600 changed members through the authoritative per-peer RIB
replacement seam on every reload: zero batch commands and 600 per-peer RIB
commands. The 100 content-stable remainder members still participated in the
authoritative snapshot pass but did not require a RIB replacement. The
candidate selected one 600-member export-only cohort and a 100-member stable
remainder on every reload. Each candidate cycle issued one batch RIB command,
zero authoritative per-peer RIB commands, and logged a committed RIB outcome.
The RIB transition took 955, 970, 953, and 973 ms; the complete PeerManager
transactions took 2594, 2223, 2598, and 2245 ms. The SIGHUP-to-`config reload
complete` walls are retained for both variants in `reload-events.csv`.

`authoritative_per_peer_rib_commands` for the base is counted from exactly
2,400 structured `outbound routes resynced` events: 600 in each reload window.
That revision did not emit an aggregate per-reload RIB-transition duration.
Candidate batch counts, cohort sizes, outcomes, and timings come from its
structured production log. `NA` preserves the absent base aggregate duration
rather than inventing one.

## Files

- `mixed-policy-reload-600-changed-100-unchanged.csv` contains the eight raw
  `reloadstall_csv` rows, prefixed only with variant and exact source SHA.
- `reload-events.csv` joins each SIGHUP timestamp to the daemon's structured
  completion event and retains operation counts and transaction timings.
- `control.csv` contains the full-fleet control-window gaps and initial RSS.
- `provenance.txt` pins source, binaries, harness, toolchain, kernel, CPU, and
  pre-run load.
- `REPRODUCE.md` gives the exact build and run shape.
- `SHA256SUMS` protects every retained input and result file in this directory.

## Teardown limitation

Measurement had already completed successfully before shutdown. On both
variants, coordinated SIGINT requested shutdown for 699 peers and logged all
700 sessions down, but only 2/700 outbound registrations cleared. The daemons
then remained CPU-busy emitting `outbound channel full or closed — marking
dirty for resync`; each was force-terminated after the condition was recorded
and its port and child processes were verified gone. This is a tracked dirty
full-table teardown defect, not part of the reload timing window. It neither
invalidates the eight pre-shutdown rows nor permits hiding the cleanup defect.
