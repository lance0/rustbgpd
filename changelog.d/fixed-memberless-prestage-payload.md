### Fixed

- Skip shared wire-payload construction for a memberless export-policy
  destination during churn. Its staged routes and reconciliation journal
  remain current for the later transition, without changing actor scheduling
  or reply deadlines.
