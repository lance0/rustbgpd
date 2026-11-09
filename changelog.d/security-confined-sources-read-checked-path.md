### Security

- Read candidate `.rpol` entry modules, `[policy] rpol_roots` and dataset files
  below `operator_only` at the canonical path the confinement check accepted,
  without resolving the named path again. A symlink retargeted, or a root or
  ancestor directory replaced by a symlink, between the check and the read can
  no longer redirect the read outside the accepted policy directories; the
  read is refused instead. Candidate configs keep the paths as written, and
  operator, boot and SIGHUP loads are unchanged.
