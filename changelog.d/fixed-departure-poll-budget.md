### Fixed

- When many non-GR sources disconnect together, update-group receivers get
  their withdrawals sooner. Each paced departure poll now covers up to 16,384
  receiver-keys and 256 members, up from 256 receiver-keys. A departure that
  starts with another PeerDown already queued sends wide batches from its
  first page. While nothing admissible waits, a group key page holds up to
  1,024 keys whatever the roster size, so a typical departure reaches each
  member once instead of once per narrow page. Receivers that run their own
  export walk stay capped at eight per poll, and queued departures still run
  one after another.
- A paced departure no longer runs its first batch of units in the same actor
  turn that tore its source down, and a run of departure units stops before a
  unit that would overrun its 10 ms budget.
