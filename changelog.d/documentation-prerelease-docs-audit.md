### Documentation

- The IXP filter-pipeline cron script and the `rs-config-render` README now
  sync only the rendered `policy/` and `datasets/` trees and install
  `config.toml` and `render-receipt.json` individually, instead of running
  `rsync --delete` over all of `/etc/rustbgpd`, which removed token files, TLS
  keys and other operator files the renderer does not emit. The IXP Manager
  route-server cookbook fetches the router document with a mode-0600 header
  file, so the API key no longer appears on `curl`'s command line.
- The gNMI reference documents the limit of 64 concurrent `Subscribe` streams
  per listener and the `RESOURCE_EXHAUSTED` status a stream beyond it gets.
  The RFC notes state that `ebgp_requires_policy` is on by default under
  `config_epoch = 2`, and quote RFC 4271's hold-time floor as the MUST it is.
  Smaller corrections cover the benchmark target inventory, the gRPC method
  inventory's InjectionService read count, the ADR index, EVPN runbook
  commands, the shipped alert list, draft pull requests and interop labs,
  readiness checkpoints, the doctor config-freshness check name and the MRT
  crate's dump retention.
