# Kernel dataplane compile-once receipt — 2026-08

Status: measurement in progress. Local correctness is green; there is no hosted performance claim yet.

## Boundary and candidate

The predeclared five-run control median is 422 seconds for the complete privileged
netns job. Within that boundary, FIB took 273 seconds and the redundant BFD
compile took 51 seconds; these observations are not acceptance evidence.

The candidate adds one internal `rustbgpd_prepare` selector immediately before
FIB. It runs the only
`cargo clean -p rustbgpd-api && cargo test -p rustbgpd --no-run`, using the
existing named target volume. Opted-in FIB and BFD then execute against those
artifacts; standalone calls retain their conservative clean-build. BFD retains
the AF_INET6-denying seccomp profile.

Public selector semantics, job/call rosters, container `--rm`, capabilities, AppArmor, cargo and target-volume identity/lifetime, and other selectors remain unchanged.

## Local correctness

A clean local proof used a fresh, uniquely named target volume, then removed it. The BFD
invocation used the workflow's AF_INET6-denying seccomp profile:

Prepare passed in 96 seconds and built the test binaries with `--no-run`; FIB passed 4 tests in 1 second (Cargo: 0.17 seconds); BFD passed its test in 2
seconds (Cargo: 0.16 seconds).

These local wall times prove artifact reuse only. Host, image, cache, and runner
conditions differ from GitHub-hosted controls, so they are not a performance
comparison.

The structural checker also rejects prepare removal/reordering, missing or misused compile-once opt-in, any second clean/compile, FIB/BFD filter drift, target-volume drift, removal of
container cleanup or privileges, AF_INET6 seccomp drift, and selector-roster
changes. Its destructive mutation suite executes each of those red paths.

## Hosted acceptance

Two GitHub-hosted attempts are required. Each must keep BFD at or below 15
seconds and the total netns job at or below 390 seconds. The candidate must
improve the five-control median by at least 8% or 35 seconds, keep all selectors
green, and show no more than 5% aggregate workflow-compute regression. A seed,
retry after unrelated runner failure, or local result cannot satisfy the gate.

Until both hosted attempts and aggregate-compute accounting pass, the verdict
remains measurement in progress.
