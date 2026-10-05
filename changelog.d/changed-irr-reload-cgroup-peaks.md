### Changed

- IRR reload receipts capture native scope and competitor container cgroup
  memory peaks through harness completion, before lifecycle probes or teardown.
  Summaries label these sources and require zero actual swap peak; historical
  receipts retain their existing timing and RSS validation.
