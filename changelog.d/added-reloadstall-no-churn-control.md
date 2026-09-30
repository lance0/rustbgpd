### Added

- The scale reload harness accepts `--no-churn` for a finite zero-reload
  control window with held sessions and no churn tasks. It checks session
  health before the existing bounded cleanup and refresh accounting.
