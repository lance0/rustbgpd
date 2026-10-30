### Upgrade notes

- The release tarball, `.deb` and `.rpm` binaries of 0.74.0 through 0.80.1
  were built with the RIB and transport benchmark instrumentation enabled.
  Those daemons run extra bookkeeping during RIB replacement work and log
  additional INFO lines from it, such as `replacement readiness scope
  finished` and `replacement capacity maximum`. Upgrade to a release built
  without it. The container image was built from the shipped packages only
  and is unaffected.
