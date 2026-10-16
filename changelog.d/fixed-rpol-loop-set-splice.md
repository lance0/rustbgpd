### Fixed

- `.rpol` set probes on a `for` loop variable or a `let` binding
  (`for c in route.communities { if c in scrub { remove community c } }`,
  `let x = route.origin-as; if x in bogons { reject }`) and loops over an
  `asn-set` now read the right set in a daemon policy chain. Releases 0.51.0
  through 0.77.0 are affected for any import or export chain whose `.rpol`
  members use these forms, including the documented scrub idiom. Chain
  assembly remapped ordinary guards into the chain's merged set tables but
  left these probes and loop bodies pointing at the member file's own table
  positions. Where that position fell inside the merged tables, the probe
  silently read another set, so the policy made the wrong decision with no
  error. Where it fell past them, route evaluation panicked. A panic in an
  import chain ended only that peer's session. A panic in an export chain, or
  in other RIB-side evaluation, stopped the RIB manager, and the daemon shut
  down as a component failure. `rbgp policy check` tests did not show the
  problem because they evaluated each policy without chain assembly.
