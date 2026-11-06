### Security

- A candidate config sent over the API could make the daemon read any file
  it can read, even from an observer (`sensitive_read`) principal through
  `DiffRuntimeConfig`, `PlanConfigTransaction` or
  `StreamPlanConfigTransaction` (`rbgp config diff` and `rbgp config plan`).
  The candidate named the file as an `.rpol` file, policy root, dataset, or
  gRPC TLS or token file. Three effects followed: a compile error echoed the
  first lines of that file, a device such as `/dev/zero` was read without a
  size limit, and a FIFO blocked the peer-manager actor until a writer
  appeared. Below `operator_only`, `.rpol`, root and dataset paths must now
  resolve under the running config's policy directories: its
  `[policy] rpol_roots` and the directories of its `.rpol` and dataset
  files. gRPC credential paths must be ones the running config already
  uses. `ApplyEvpnRuntime` candidates are held to the same limits. Operator
  callers can still stage candidate sources elsewhere, as `rs-config-render`
  does. For every API caller, errors for those files give the path, line
  and column and the compiler stage, without file text. Every `.rpol`,
  dataset and gRPC credential read during a config load, including on-disk
  loads, now refuses anything but a regular file without waiting on it and
  stops at a size bound. Diff and plan load the candidate on the blocking
  pool, so the peer-manager actor keeps serving other requests while it
  loads.
