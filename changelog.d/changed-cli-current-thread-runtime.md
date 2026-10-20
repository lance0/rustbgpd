### Changed

- `rbgp` runs on a single-threaded async runtime instead of starting one
  worker thread per host CPU on every invocation, so one-shot commands start
  faster and their startup cost no longer grows with the host's core count.
  Scripts, exporters, and probes that call `rbgp` in a loop benefit most.
