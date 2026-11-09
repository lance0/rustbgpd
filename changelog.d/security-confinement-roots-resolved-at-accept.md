### Security

- Resolve the policy directories that confine candidate sources below
  `operator_only` once, when the config is read at boot or SIGHUP, instead of
  again for every candidate; API commits keep the directories already
  resolved. A nested policy directory replaced by a symlink after the config
  was accepted no longer extends the confinement to the symlink's target. A
  `[policy] rpol_roots` entry that is a regular file admits only that file: a
  candidate may name it, but its imports do not resolve into the surrounding
  directory. Operator, boot and SIGHUP loads are unchanged.
