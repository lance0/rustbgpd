### Changed

- The `reloadstall` harness links jemalloc as its global allocator, matching
  the daemon. Its stub readers reallocating frame and NLRI buffers at once
  under a coalesced post-reload burst contended on glibc's malloc arena lock,
  which made completion medians bimodal between process starts. Receiver-bound
  receipts recorded with glibc malloc are not directly comparable on
  completion time. See
  [`bench/scale/reloadstall/README.md`](../bench/scale/reloadstall/README.md).
