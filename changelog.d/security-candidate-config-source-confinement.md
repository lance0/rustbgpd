### Security

- A candidate config sent over the API could name any file the daemon can
  read as an `.rpol` file, policy root or dataset, even from an observer
  (`sensitive_read`) principal through `DiffRuntimeConfig`,
  `PlanConfigTransaction` or `StreamPlanConfigTransaction`. Three effects
  followed: a compile error echoed the first lines of that file, a device
  such as `/dev/zero` was read without a size limit, and a FIFO blocked the
  peer-manager actor until a writer appeared. Below `operator_only`, those
  paths must now resolve under the running config's policy directories: its
  `[policy] rpol_roots` and the directories of its `.rpol` and dataset
  files. `ApplyEvpnRuntime` candidates are held to the same directories.
  Operator callers can still stage candidate sources elsewhere, as
  `rs-config-render` does. For every API caller, errors for those files
  give the path, line and column and the compiler stage, without file text.
  Every `.rpol` and dataset read, including on-disk config loads, now
  refuses anything but a regular file without waiting on it, and stops at
  the configured size budget. Diff and plan load the candidate on the
  blocking pool, so the peer-manager actor keeps serving other requests
  while it loads.
