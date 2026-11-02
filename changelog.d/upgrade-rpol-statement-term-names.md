### Upgrade notes

- **Some `.rpol` term rows are renamed.** A term that lowers to one row
  keeps its name, and so does the common modify-then-accept term
  `term tag { add community 65000:1; accept }`. The renamed rows fall into
  three groups:
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
- Dashboards and alerts that select `rbgp policy stats` or `GetPolicyStats`
  rows by `.rpol` term name, and the evaluation-error text
  `... in policy P term T`, need the new names; run `rbgp policy stats`
  after the upgrade to read them.
