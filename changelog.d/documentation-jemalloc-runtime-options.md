### Documentation

- Document that the default jemalloc build reads run-time allocator options
  from `_RJEM_MALLOC_CONF` and ignores `MALLOC_CONF`, and add a heap-profiling
  how-to using jemalloc's built-in profiler and `jeprof`. See
  [`docs/benchmarks.md`](../docs/benchmarks.md#heap-profiling-with-jemalloc).
