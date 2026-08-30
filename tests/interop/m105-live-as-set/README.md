# M105 live AS_SET discovery

M105 sends the same two IPv4 routes from one raw route-server client to five
current route-server implementations: rustbgpd, BIRD 3.3.2, OpenBGPD 9.2,
GoBGP 4.8.0, and FRR 10.3.1. The first route has an ordinary AS_SEQUENCE; the
second has a two-member AS_SET. No daemon's AS_SET policy default is changed.

The live driver records whether each receiver installs the AS_SET route, checks
that the session and process remain live, withdraws both routes, and saves the
observations beside packet-level evidence. It does not encode an expected
per-daemon outcome.

Run from the repository root:

```console
containerlab deploy -t tests/interop/m105-live-as-set.clab.yml
M105_ARTIFACT_DIR="$HOME/artifacts/m105-live-as-set-$(date -u +%Y%m%dT%H%M%SZ)" \
  bash tests/interop/scripts/test-m105-live-as-set.sh
```

The artifact directory contains image/config identities, the raw-peer event
log, the PCAP and decoded payload rows, the packet-oracle receipt, and the
per-daemon outcome matrix. The artifact directory is not checked in. This
manual observation is indexed from the public interop, receipt, and evaluation
pages, but remains outside hosted CI and is not a conformance ranking.

## Current observation

Repeated local runs on 2026-08-29 produced the same receiver matrix:

| Receiver | AS_SET route |
|---|---|
| rustbgpd 0.67.0 | Not installed |
| BIRD 3.3.2 | Not installed |
| OpenBGPD 9.2 | Not installed |
| GoBGP 4.8.0 | Installed in accepted Adj-RIB-In |
| FRR 10.3.1 | Installed |

All five sessions remained Established, the ordinary AS_SEQUENCE control was
accepted by all five receivers, and both prefixes disappeared after the raw
client withdrew them. “Not installed” deliberately does not guess whether an
implementation classified the UPDATE as a policy rejection or
treat-as-withdraw; the native receiver snapshots only establish absence from the
accepted route surface.
