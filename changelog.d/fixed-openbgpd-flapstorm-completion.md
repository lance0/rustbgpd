### Fixed

- Let OpenBGPD flapstorm matrix cells complete rejoin on exact table coverage
  when the non-GR stub receives no End-of-RIB, reporting its absence explicitly.
  Other cells retain the End-of-RIB requirement; missing coverage still fails.
