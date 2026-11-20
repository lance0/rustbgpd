### Documentation

- A new [RIB lifecycle](../docs/reference/rib-lifecycle.md) reference page
  follows a session through the RIB stage by stage. It opens with a matrix
  of session shape against stage that names the longest unit of work in
  each cell and marks it paced (other peers' updates run in between),
  bounded turns (they do not), one table-sized turn, or not measured, with
  the test or receipt behind every paced mark. This first part covers a
  session coming up, steady state and a session ending.
- A new [receipt](../docs/perf/first-group-build-registration-2026-11.md)
  publishes the paced first-group build measurement. At 1M routes, during
  the first policy-free plain-unicast group build, unrelated UPDATE
  latency fell from 2,209 ms to 0.60 ms. Sessions with export policy, a
  configured role, per-client-best, or mixed families can still take the
  synchronous build path.
