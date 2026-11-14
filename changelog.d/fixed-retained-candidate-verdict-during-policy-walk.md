### Fixed

- A refused export-policy change no longer ends as an ambiguous rollback
  because a retained dynamic neighbor's collision candidate won while the
  change was rolling back. When the candidate's OPEN arrived during the
  rollback, its verdict moved the neighbor onto the candidate's RIB identity
  after the rollback had named the old one. The restore's acknowledgement
  then no longer matched the neighbor, and the rollback reported
  `policy_rollback_batch_reply_lost` instead of a full compensation. While
  a policy change runs, the OPEN of such a neighbor is now held until the
  change has committed or rolled back, as the removal of a dynamic neighbor
  already is.
  **Operator-visible:** during a long policy change, a held candidate can
  reach its collision-verdict timeout and fall to Idle; the neighbor then
  reconnects.
