### Changed

- A new single-best unicast update-group member receives large initial tables
  in pages. The RIB can process other peers' updates between pages. A member
  whose writer fills resumes from its admitted routes, and receives End-of-RIB
  after its initial routes. A source session going down during the join, or
  more concurrent changes than the replay's change log holds, is sent with the
  remaining pages instead of restarting the member's whole table. A departure
  or burst that changes more than about 4,096 best paths during the join
  rewinds the member into a paced reconcile of its table instead of a
  one-turn resync, and End-of-RIB still follows the complete table. Churn
  that overflows the reconcile on more than 8 rescans takes one resync,
  counted with cause `lag`.
