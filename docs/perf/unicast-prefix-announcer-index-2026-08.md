# Unicast prefix announcer index receipt (2026-08)

This receipt compares base `812770e5297f6c455e457f158d057528f6bcf4fb`
(tree `e8d586c1623d1f1cda0374117e7c9755321a04b7`) with head
`5ed4d093d8985207108a463a6cc06e959a598457` (tree
`9ccd399cf64bd97301d1609ffd881b4244eb3763`). The head compacts the
prefix-to-announcing-peers index around its common singleton shape.

At 100,000 prefixes, requested live allocator bytes fell from 7,471,120 to
3,801,336 with one announcer (49.12%), and from 10,871,120 to 6,947,064 with
two announcers (36.10%). Each value repeated exactly three times. These are
fresh-process requested live allocator-byte deltas for the isolated index
fixture, not daemon RSS measurements.

Three admitted rrharness campaigns supplied six paired observations per rung.
The frozen no-regression test computes each pair's head improvement percentage,
negates it to regression percentage, and applies the one-sided 95% Student-t
upper bound `mean + 2.0150483733 * sample_stdev / sqrt(6)`. The maximum allowed
regression UCL is +5%. Observed UCLs were -3.771671% (churn 256), -7.347941%
(churn 1000), +0.625726% (flood 256), and +1.744210% (flood 1000): all pass.
This is a bounded no-regression gate, not a claim of universal throughput
speedup. An earlier campaign was refused after four cells when load remained
above the admission ceiling; none of its partial observations are included.

The checked-in [artifact](artifacts/unicast-prefix-announcer-index-2026-08/README.md)
contains all input rows, hashes, limits, and a standard-library verifier.
