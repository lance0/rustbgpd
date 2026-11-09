### Upgrade notes

- Below `operator_only`, a `[policy] rpol_roots` entry that is a regular file
  is now only a path a candidate can name. A candidate sent over the API,
  including a non-operator `rbgp config diff`, is refused when another module
  imports that file, or when the file's own `import` lines are written
  relative to its directory, unless a policy directory covers that
  directory. List the directory in `rpol_roots` and reload. Operator callers
  and boot and SIGHUP loads are unaffected. See the
  [reload matrix](../docs/reference/reload-matrix.md).
