### Changed

- After a non-GR source disconnects, the RIB sends larger unicast and
  FlowSpec withdrawal batches while its primary queue is empty. A queued
  update narrows delivery immediately and can apply at the next completed
  page when its routes are independent of the departure.
