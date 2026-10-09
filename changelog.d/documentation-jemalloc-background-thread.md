### Documentation

- Record a same-session A/B of jemalloc's `background_thread:true` against
  the defaults on the S2, IRR reload, and operator-read cells. It raised the
  median daemon cgroup memory peak by 177 MiB (S2) and 93 MiB (IRR) for IRR
  reloads 17–30 ms faster, so the daemon keeps jemalloc's defaults. See the
  [receipt](../docs/perf/jemalloc-runtime-options-2026-10.md).
