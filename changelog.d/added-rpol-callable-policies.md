### Added

- `.rpol` policies can call other policies: `apply NAME` or
  `apply NAME(args)` as a statement runs the called policy's terms in
  place, the IOS-XR RPL policy-library idiom. Its `reject` denies the
  route; its `accept`, or falling off its end, returns to the caller,
  unless it declares `default-action reject`. Its writes stage into the
  caller while every condition reads the route as received. Calls work
  in term, `if` and `for` bodies, may nest, and share the `apply` cycle,
  depth and size limits. Inlined terms appear in explain, test hits and
  `rbgp policy stats` as `<term>.<n>/<call>:<called-term>`. `apply(NAME)`
  stays the predicate, and a policy that holds an `apply` statement cannot
  be one. See
  [`apply` as a statement](../docs/reference/rpol-language.md#apply-as-a-statement--calling-a-policy).
