### Fixed

- An export-policy reload under steady route churn again stages the shared
  destination update group before the RIB transition fence. The RIB advanced
  that unfenced staging only while no UPDATE was queued, so churn that kept
  the queue non-empty could delay it past its 5 s reply deadline. The fenced
  transition then repeated the full staging walk while queued UPDATEs waited
  behind the fence. Queued UPDATEs now keep priority for one 25 ms poll
  budget, after which the staging walk takes its next slice.
