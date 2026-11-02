### Upgrade notes

- **Some `.rpol` term rows are renamed.** A term with more than one
  statement now numbers its rows by statement. The common case is a term
  that modifies and then accepts, such as
  `term tag { add community 65000:1; accept }`: its row was `tag` and is now
  `tag.2`, the position of the `accept`. A term with one statement keeps its
  names, so `term t { if A { accept } else { reject } }` still gives `t.1`
  and `t.2`. Rows under `apply` calls gain the statement too, for example
  `t.2/lib:bad` becomes `t.1.2/lib:bad`. Dashboards and alerts that select
  `rbgp policy stats` or `GetPolicyStats` rows by term name, and the
  evaluation-error text `... in policy P term T`, need the new names; run
  `rbgp policy stats` after the upgrade to read them.
