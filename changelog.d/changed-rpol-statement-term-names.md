### Changed

- **Breaking:** `.rpol` explain traces, `rbgp policy test` term hits and
  `rbgp policy stats` rows name each lowered term after the source statement
  it executes. One row of the term's final statement keeps the bare term
  name: the last row holding its own `accept` or `reject`, else its last
  row. Every other row is `<term>.<statement>`, with `.<k>` only when that
  one statement lowers to several terms. Names used to number every lowered
  term of a source term in order, so a compiler change to how one statement
  lowered renamed the rows of every later statement; now a lowering change
  that keeps the source term and its final statement never renames the
  bare row. A term name cannot contain `.`, so no source term can take a
  generated name. The decision corpus now pins every row's name and
  contents. See
  [Term-name rulings](../docs/reference/rpol-language.md#term-name-rulings).
