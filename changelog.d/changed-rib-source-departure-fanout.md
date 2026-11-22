### Changed

- After a source session goes down without graceful restart, the RIB sends
  large unicast and FlowSpec changes in batches. An unrelated unicast
  UPDATE at the head of the input queue can be applied between batches.
