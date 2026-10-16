### Fixed

- `.rpol` set probes on a `for` loop variable or a `let` binding
  (`for c in route.communities { if c in scrub { remove community c } }`,
  `let x = route.origin-as; if x in bogons { reject }`) and loops over an
  `asn-set` now read the right set in a daemon policy chain. Chain assembly
  remapped ordinary guards into the chain's merged set tables but left these
  probes and loop bodies pointing at the member file's own table positions,
  so they read another set, or indexed past the merged tables and panicked
  during route evaluation. `rbgp policy check` tests were unaffected because
  they evaluated the member without chain assembly.
