# Kernel dataplane compile-once receipt — 2026-08

Status: NO-GO. Local correctness is green, but the predeclared two-attempt aggregate gate did not pass.

## Boundary and candidate

The predeclared controls were run/job `30806738909/91663744751`, `30815271882/91691417967`, `30823070482/91717624804`,
`30833928077/91754355578`, and `30781164612/91585922738`: 409/412/422/424/427 seconds (median 422).
Within that cohort, FIB's median was 273 seconds and redundant BFD's was 51 seconds.

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

Two hosted attempts must each keep BFD <=15 seconds and netns <=390 seconds, save at least 35 seconds against the 422-second median, and keep every selector green.
For each attempt, `C(run)` is the sum of raw `completed_at - started_at` seconds across the identical 31-job Kernel Dataplane roster; queue time is excluded.
Both attempts must keep `C(run) <= 2912`, or 105% of the 2774-second control-aggregate median; the verdict uses the slower candidate aggregate.
Any failed, cancelled, missing-timestamp, runner-failure, or roster-mismatched attempt is invalid; jobs are never spliced across attempts.
A seed, retry after unrelated runner failure, or local result cannot satisfy the gate.

Run/job `30849663483/91806407214` passed at 355 seconds (FIB 1, BFD 3; `C=2758`); `30849975385/91807352207` passed at 354 seconds (FIB 1, BFD 3) but `C=3016` exceeded 2912.
The affected lane saved 67–68 seconds twice, but the full-workflow attempts disagreed under the frozen guard. The candidate is closed without a performance claim or merge.
