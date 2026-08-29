# M103 — GoBGP 4.8 route-server differential

M103 is a sibling of M92, not a replacement. It re-runs the same dual-stack
route-server differential with GoBGP 4.8.0 while keeping every M92 topology,
driver, config, raw capture, golden, and historical receipt byte-for-byte
unchanged.

Two GoBGP sources inject five routes into a GoBGP incumbent and rustbgpd
candidate. An independent BIRD 2.0.12 target receives four baseline routes.
The normal proof uses fresh baseline, one-line rustbgpd export-mutant, and
byte-identical restore rounds. It must finish exactly 56/0. A separate fresh
deployment disables graceful restart only on GoBGP's target neighbor; routes
remain present, both GoBGP EoRs are absent, and the proof refuses to capture or
diff. That negative must finish exactly 17/0.

## Run after review authorization

```bash
docker build --target dev -t rustbgpd:dev .
docker build -t bird:2-bookworm -f tests/interop/Dockerfile.bird tests/interop
docker build \
  --build-arg GOBGP_VERSION=4.8.0 \
  --build-arg GOBGP_SHA256=43b570ae5cc1afab7aebdd9d8f4536e27656465848270c8a6f5fda1ffe093a03 \
  -t gobgp:v4.8.0-m103 -f tests/interop/Dockerfile.gobgp-v47 tests/interop
containerlab deploy -t tests/interop/m103-gobgp-v48-rs-differential.clab.yml
bash tests/interop/scripts/test-m103-gobgp-v48-rs-differential.sh
containerlab destroy -t tests/interop/m103-gobgp-v48-rs-differential.clab.yml

containerlab deploy -t tests/interop/m103-gobgp-v48-rs-differential.clab.yml
M103_COMPLETENESS_NEGATIVE=1 \
  bash tests/interop/scripts/test-m103-gobgp-v48-rs-differential.sh
containerlab destroy -t tests/interop/m103-gobgp-v48-rs-differential.clab.yml
```

Set `M103_ARTIFACT_DIR` to a new absolute path when durable evidence is
required. The driver rejects relative or pre-existing destinations, builds and
validates a sibling staging directory, atomically renames it only after a
successful exact ledger, and then lets the existing EXIT cleanup remove
`WORK`, daemons, and the lab. Failed runs export nothing. Hosted CI selects two
runner-temporary destinations and uploads each only after its corresponding
single-attempt run succeeds.

The normal artifact contains the exact before/after GoBGP raw JSON, a file with
their recursive-`age`-only canonical hashes, generated M103 ribsnap, diff JSON,
and incumbent/candidate PDML for each of baseline, mutant, and restore. It also
contains the verified runtime/image/config identity document, plain transcript,
exact ledger, and a SHA-256 manifest. The negative artifact is deliberately
smaller: identity, transcript, 17/0 ledger, and the two bounded EoR verifier
outputs only. It contains no raw JSON, ribsnap, diff, or PDML and therefore does
not imply that the refused comparison ran. Exact inventories, parseability,
canonical hashes, verdicts, size bounds, and the manifest are revalidated
before either destination becomes visible.

The driver preflights all identities and inputs before starting any BGP daemon.
All three GoBGP containers must use the same local `gobgp:v4.8.0-m103` image,
run on `x86_64`, report exact `gobgp` and `gobgpd` 4.8.0 versions, and contain
the pinned binary bytes. BIRD must report 2.0.12. The five reused M92 configs
must match the current checked-in hashes on the host and through their
read-only container mounts.

## Cross-version oracle

`gobgp-v48-m103-adjout.json` is the deterministic, age-normalized M103 raw
oracle. It was derived from the archived M92 GoBGP 4.7 raw object by recursive
deletion of only the volatile `age` member; it is not represented as a prior
live 4.8 capture. Every live 4.8 before/after capture must compare byte-for-byte
with both this oracle and the archived 4.7 capture after that same single
recursive deletion. No other field is ignored, normalized, projected, or
reordered after `jq -S` serialization.

The live 4.8 capture is converted with source
`m103-gobgp-v4.8-incumbent` and generation `103`, then compared byte-for-byte
with `gobgp-v48-m103.expected.ndjson`. Offline tests additionally require its
four route records and trailer to be byte-identical to M92; only the versioned
header source and generation differ. Any other raw or golden delta stops the
proof.

## Pinned inputs

| Input | SHA-256 |
|---|---|
| official GoBGP 4.8.0 amd64 archive | `43b570ae5cc1afab7aebdd9d8f4536e27656465848270c8a6f5fda1ffe093a03` |
| `/usr/local/bin/gobgp` | `5bd2c6eddab475746d5257c4466f8377b3790bcf7159e18e03a9d44a1685348b` |
| `/usr/local/bin/gobgpd` | `710b7c28d2b83aef887cc28ae6ddcffe82f11a27e0ba263d9f747658b45f8a97` |
| current rustbgpd config | `ac79814f81dee293acba58dd112086c6c0eda6f83a18526d122261a509a46141` |
| GoBGP RS config | `cf4061b00f13c4b5bdb369af5fa2b8648b48b1296bae456349fe8dacc027b925` |
| GoBGP source1 config | `b73b64105cad2d222825285bfad93813a33ff72dac09dabafb2bc6b24ac5d4c3` |
| GoBGP source2 config | `27b9e7036645e00fc1b779bb05a1402e5adf70578f88c405287dac44e885d7e1` |
| BIRD target config | `61fbbba70926ec33589aef64ec1a9adc374ec953bdd732a6bce41df059c77d1b` |
| archived GoBGP 4.7 raw | `ab8d50f0f7e468837e93d85a6ff69640f2937535db71c28fe5c624ed0d794c84` |
| M103 age-normalized GoBGP 4.8 raw oracle | `ba8ba57929ea2add127682fac599914a3baf083e44140e9165e9cd61546173db` |
| M103 expected ribsnap | `fd30efb01c8967d0ba335c864dc38f6e6922ad93413fd2b0ef9d9755f3f6c830` |

M92's archived rustbgpd config was
`957f6630f1f52d1e4030523661ba653b41253ba2a2a961c09b508fcdf99c373a`.
The current hash differs because the test-only tier-auth token plumbing moved;
M103 records both values and never restores or describes the historical file
as current. The four GoBGP/BIRD config hashes remain the archived values.

The M103 receipt is synthetic interoperability evidence. It does not replace
the demand-gated external shadow/canary pilot. Completion requires one hosted
normal run, one hosted negative run, unchanged M92 success, and cleanup with no
remaining M103 containers or network.
