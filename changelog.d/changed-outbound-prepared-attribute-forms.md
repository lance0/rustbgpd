### Changed

- Prepare each unicast route's outbound attributes once, in the form its
  UPDATE uses, instead of keeping both the `NEXT_HOP` and the `MP_REACH_NLRI`
  form for every route in a slice. A session sending a slice of distinct
  routes with large attribute sets requests about half the transient memory
  it did. Grouping, order and wire output are unchanged.
