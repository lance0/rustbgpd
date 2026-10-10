# Policy-stats Q1 release follow-up — 2026-10-10

Prepared before the confirmation window. This is a short confirmation of the
retained J2 Q1 result, not a replacement for its 24 reloads per arm.

- Arm A: #2952 parent `3bbc1576cc3fd1f97a6c723131f183f82d4952f4`.
- Arm B: #2952 `49abbb0171cbb889b7e2618c2bdcec6ea35699ae`.
- Shared cell and `reloadstall`: `591ac39d4b50fc2c647942713a9ea99c0588a51a`.
- ABBA, four reloads per run, two runs/eight reloads per arm. Only `RELOADS=4`
  changes: 1,000 peers × 400,000 total prefixes, 40 s quiescence, 15 s control,
  daemon CPUs 2–3, generator 4–5, probes 8–15, pair lead 110 ms.
- Hold the canonical host lock throughout, retain the unmodified quiet gate
  for each run, check the retained binary roster before starting. No builds,
  competing daemon, or other measurement in the reserved window.
- Retain full daemon/harness/probe logs, all exits, environment, timestamps,
  summaries and hashes. Every existing cell criterion must pass. Any failed
  cell or missing reload invalidates the confirmation; retain it and report it.
- Report medians/ranges per run and pooled, without treating correlated
  reloads as independent samples. Check whether both B runs reproduce the
  shorter RIB timer and long post-commit/cohort cases. Describe any contrary
  case. No significance claim from two runs per arm.
- Attribute time using each reload's actual wall timestamps. Phase medians
  are non-additive. A RIB committed log is not proof the reply was delivered
  at that timestamp: terminal input retirement precedes `reply.send`.
- Distinguish observed wait outside the logged RIB transition from the
  source-consistent encoding/scheduling explanation; there is no per-task
  profiler in this confirmation.
- Release decision: classify the observed workload, and distinguish a
  release blocker from a restriction on an end-to-end performance claim.
- S2 and IRR main/v0.75.0 quiet-host measurements are preparation only and
  must not be launched by this confirmation.
