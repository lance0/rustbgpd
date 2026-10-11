### Changed

- RIB readiness checkpoints use channel wake notifications to skip the owner
  mutex during steady idle service, while retaining the existing readiness and
  summary budgets during route replay and policy replacement.
