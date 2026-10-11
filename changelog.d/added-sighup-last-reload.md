### Added

- `rbgp config last-reload` and `rbgp doctor` expose the latest SIGHUP result,
  including a closed failure reason and bounded applied/unapplied operation
  identities for partial reloads. gRPC credential publication is recorded as an
  applied operation on success or a known partial result on failure. Doctor also
  warns when the retained reload task fails.
