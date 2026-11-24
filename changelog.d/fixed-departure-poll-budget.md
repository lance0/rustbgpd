### Fixed

- When many non-GR sources disconnect together, update-group receivers get
  their withdrawals sooner. Each paced departure poll now covers up to 16,384
  receiver-keys, up from 256. A departure that starts with another PeerDown
  already queued sends wide batches from its first page. Receivers that run
  their own export walk stay capped at eight per poll, and queued departures
  still run one after another.
