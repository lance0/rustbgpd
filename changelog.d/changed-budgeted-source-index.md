### Changed

- Clean export-policy reloads prune the departed source group's unicast prefix index in bounded actor turns after the commit fence. Readiness, ordinary updates and queries continue while the detached index retires; active group membership and gauges retain their existing commit points.
