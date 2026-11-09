### Security

- Resolve the policy directories that confine candidate sources below
  `operator_only` once, when the config is read at boot or SIGHUP, instead of
  again for every candidate. They hold until the next accepted reload, which
  resolves them again; API commits keep the directories already resolved. A
  nested policy directory replaced by a symlink in between no longer extends
  the confinement to the symlink's target. Whether each `[policy] rpol_roots`
  entry is a directory or a file is fixed at the same time. An entry that is a
  regular file admits only that file as a path a candidate names: another
  module cannot import it, its own imports are looked up only under the
  candidate's policy directories and not relative to its directory, and a
  directory later put in its place is not a policy directory. The file each
  gRPC credential path resolved to at boot or SIGHUP stays out of candidate
  sources until the next accepted reload, across API commits, and so does
  the file the path resolves to when a candidate is loaded; a credential
  symlink rotated in between keeps both targets out. A credential file moved
  aside by rename is not covered under its new name. Operator, boot and
  SIGHUP loads are unchanged.
