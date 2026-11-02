### Changed

- **Breaking:** `.rpol` explain traces, `rbgp policy test` term hits and
  `rbgp policy stats` rows name each lowered term after the source statement
  it executes, `<term>.<statement>`, with `.<k>` only when that one statement
  lowers to several terms. Names used to number every lowered term of a
  source term in order, so a compiler change to how one statement lowers
  renamed the rows of every later statement. The decision corpus now pins
  the names. See
  [Lowering into the IR](../docs/reference/rpol-language.md#lowering-into-the-ir-normative).
