# M83 initial-table End-of-RIB oracle receipt

Date: 2026-07-27

## Question

M83 twice observed an NLRI-bearing UPDATE after the IPv4 End-of-RIB in one
hosted run. The old oracle compared the End-of-RIB with the last NLRI after the
last RS-to-BIRD OPEN across the whole capture. That could not distinguish an
initial-table ordering defect from another TCP stream or a legal live delta
after the initial update.

## Controlled shape

The same measured harness tree is commit `9549d4e0`. It:

- disables BIRD's two member-route static protocols and waits for rustbgpd's
  received inventory from BIRD to become empty;
- snapshots and requires the known, nonempty Adj-RIB-Out toward BIRD:
  `100.66.0.0/24`, `100.67.0.0/24`, and `100.70.0.0/24`;
- bounces only the BIRD BGP session;
- selects the final RS-to-BIRD OPEN and scopes all initial-table events to its
  `tcp.stream`;
- requires the exact three-prefix set before that stream's single IPv4
  End-of-RIB, without treating later same-stream NLRIs as part of the initial
  update.

Two production revisions were run six times each, serialized on the same host:

| side | production revision | image ID |
|---|---|---|
| pre-change control | `68212e14eab4aeec1bbf8aee42fe4092dd21cc5f` | `sha256:1af387d49ce86305a8046878048abd38ac52df0c49bca27012266ae57c983028` |
| then-current main | `06ce6da8889acd01bfe0e52cddf0bce17c437bc8` | `sha256:4b877e71f173f933608833d694210c9d43f15e785986b05d4e34c0ed35fa4507` |

Each run retained the pcap, filtered PDML, exact expected and advertised
inventories, compact stream-aware event trace, BIRD/tshark/rustbgpd logs, both
oracle outputs and exit codes, metadata, and per-run SHA-256 manifest. The
combined digest of the twelve ordered per-run manifests is
`676157e503b3cfdb9cc7a8776b288d87fc6dfada6dce3ad00c8bd313a7025839`.

## Result

| side | full M83 receipt | corrected oracle | legacy oracle |
|---|---:|---:|---:|
| pre-change control | 6/6 pass | 6/6 pass | 6/6 pass |
| then-current main | 6/6 pass | 6/6 pass | 6/6 pass |

Every corrected run observed exactly three expected prefixes before EoR on one
stream. The EoR and final initial NLRI were adjacent PDUs in every capture.

The earlier intermittent legacy failure did not reproduce after member
origination was quiesced. This campaign therefore found no control/current
product divergence and supports correcting the receipt boundary. It does not
claim that the old cross-stream, post-EoR event was impossible or that a legal
live delta can never follow EoR.

## Load-bearing proofs

The cheap self-test is part of the per-commit Rust test gate. Its fixtures go
red for these exact regressions:

- remove `tcp.stream` scoping: an old-stream `198.51.100.0/24` update enters
  the target initial inventory;
- include post-EoR target-stream NLRIs: live `192.0.2.0/24` becomes an
  unexpected initial prefix;
- bypass exact prefix-set equality: the missing, expected-after-EoR, and
  unexpected-prefix fixtures pass;
- compare only frame numbers: the same-frame EoR-before-prefix fixture is no
  longer distinguishable.

Failed hosted attempts are uploaded with `if: always()` so future failures
retain the same packet, inventory, event, and daemon evidence.
