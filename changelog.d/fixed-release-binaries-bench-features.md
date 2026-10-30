### Fixed

- Build the release tarballs and the `.deb` and `.rpm` packages from the
  shipped packages only (`rustbgpd`, `rbgp`, `rs-config-render`,
  `birdwatcher-adapter`) instead of the whole workspace. The workspace build
  also selected the scale benchmark harnesses, and Cargo feature unification
  compiled the shipped daemon with the RIB's benchmark instrumentation. A
  release gate and a pull-request check now fail if the release build
  resolves the `bench-internals` feature for any package.
