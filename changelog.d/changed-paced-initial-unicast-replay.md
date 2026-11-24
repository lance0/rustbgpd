### Changed

- A new single-best unicast update-group member receives large initial tables
  in pages. The RIB can process other peers' updates between pages. A member
  whose writer fills resumes from its admitted routes, and receives End-of-RIB
  after its initial routes. A source session going down during the join, or
  more concurrent changes than the replay's change log holds, is sent with the
  remaining pages instead of restarting the member's whole table. A departure
  that changes more than about 4,096 best paths, or more than 1,024 new
  prefixes arriving during the join, still falls back to a full resync of the
  member's table.
