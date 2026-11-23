### Changed

- A paced withdrawal after a non-GR source disconnects no longer takes a
  forced readiness checkpoint for each receiver and prefix that has no
  policy-filtered candidate, which shortens convergence for private
  receivers.
