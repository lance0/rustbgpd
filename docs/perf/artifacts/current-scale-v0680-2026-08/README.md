# Current v0.68.0 scale compact artifacts

This bundle retains compact source-equivalent v0.68.0 evidence for the IXP-700
S2/S3 cells, route-server-1000, and three RR1000 runs. The measured source was
`ba5717b4ad8f921e85a96168b51e0e9169585271`; its delta from exact v0.68.0 is
limited to two workflow files and four checkout-depth lines, leaving product
and benchmark inputs identical.

The IXP logs are sanitized timing output. `route-server-1000-summary.csv`
retains the compact status, timing, RSS, and readiness-probe result, while the
two environment files retain its status and provenance. The RR1000 JSON records
each fixed-shape phase result.
