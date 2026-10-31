### Fixed

- Release the outbound updates still queued for a session when it goes down
  through the same paced release as its active update, one slice per step on
  a separate task. Before, the teardown dropped the whole queue in one
  session turn, so a slow peer left holding the last reference to a queued
  full-table inventory freed every route at once. The close drain keeps its
  250 ms budget, and the queued updates are still discarded unsent.
