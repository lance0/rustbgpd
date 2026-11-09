### Security

- Resolve the policy directories that confine candidate sources below
  `operator_only` once, when the config is read at boot or SIGHUP, instead of
  again for every candidate. They hold until the next accepted reload, which
  resolves them again; API commits keep the directories already resolved. A
  nested policy directory replaced by a symlink in between no longer extends
  the confinement to the symlink's target. Whether each `[policy] rpol_roots`
  entry is a directory or a file is fixed at the same time. An entry that is a
  regular file admits only that file: a candidate may name it, but its
  imports do not resolve into the surrounding directory, and a directory
  later put in its place is not a policy directory. gRPC credential paths are
  resolved again for every candidate, so a credential symlink rotated between
  reloads keeps both its old and its new target out of candidate sources.
  Operator, boot and SIGHUP loads are unchanged.
