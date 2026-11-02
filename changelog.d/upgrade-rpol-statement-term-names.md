### Upgrade notes

- **Some `.rpol` term rows are renamed.** A term whose only row comes from
  its final statement keeps its name, and so does the common
  modify-then-accept term `term tag { add community 65000:1; accept }`.
  The renamed rows fall into four groups:
  - A final statement after earlier statements that lower to rows of their
    own takes the bare name:
    `term t { set med 10; if A { accept } }` gave `t.1` and `t.2` and now
    gives `t.1` and `t`.
  - A final statement that lowers to several rows gives the bare name to
    its last `accept` or `reject`, else its last row:
    `term t { if A { accept } else { reject } }` gave `t.1` and `t.2` and
    now gives `t.1` and `t`, and the last branch of a four-branch
    `else if` chain changes from `t.4` to `t`.
  - An earlier statement that lowers to several rows numbers them under
    the statement:
    `term pad { set med padded(route.as-path.len); accept }`, whose
    function call lowers to six rows, gives `pad.1.1` to `pad.1.6` and
    `pad` instead of `pad.1` to `pad.7`.
  - A final statement that lowers to no row, such as an `if` with an empty
    body and no `else`, leaves no bare row even when the term has one row:
    `term x { set med 5; if route.med >= 9 { } }` gave `x` and now gives
    `x.1`.
- **A name that still exists can now name a different row.** `.<n>` is now
  a statement number, not a row position. In
  `term t { set local-pref 500; let x = route.med - 100; set med x; accept }`
  the `let` was `t.1` and the `accept` was `t.2`; now the `let` is `t.2`,
  its statement number, and the `accept` is `t`. A dashboard or alert
  keyed on `t.2` keeps resolving but reads another row, so check every
  selected name against `rbgp policy stats` after the upgrade, not only
  the missing ones.
- The new names appear wherever a lowered term is named: explain traces,
  `rbgp policy test` term hits, `rbgp policy stats` and `GetPolicyStats`
  rows, the evaluation-error text `... in policy P term T`, and the
  config-reload reason `import|export rpol policy P term T changed`.
