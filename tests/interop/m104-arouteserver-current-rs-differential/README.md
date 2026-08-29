# M104 — current ARouteServer route-server differential

M104 is a sibling of the historical M90 receipt. It does not revise M90 or
replace its evidence. It reuses M90's site inputs, GoBGP member configs, and
11-row announcement corpus read-only while moving the daemon boundary to:

| Component | Exact boundary |
|---|---|
| ARouteServer | Python package 1.23.2; Docker schema-2 manifest `sha256:ba0e9c0b541c63acf0765a08fd2e09c2bba9dc64af1f5bbdce7819e8d1c34d66`; image config `sha256:4a08ef740f00a119f5897b0f834da9ff172a282c93d47fdff636c3b50c9aec93`; upstream `v1.23.2` commit `85f24252564822556bd93cb9eba1f73d1e8268ea` |
| BIRD | 2.19.2 source archive SHA-256 `aff89abba3b92b7637bd57e0168b8d7ae887747f160ada4973378ad72f5f3660`, staged by the shared producer before image build; ARouteServer target 2.16; exact runtime version plus `bird -p` before daemon start |
| GoBGP | 4.8.0 release archive SHA-256 `43b570ae5cc1afab7aebdd9d8f4536e27656465848270c8a6f5fda1ffe093a03`; `gobgp` binary SHA-256 `5bd2c6eddab475746d5257c4466f8377b3790bcf7159e18e03a9d44a1685348b`; `gobgpd` binary SHA-256 `710b7c28d2b83aef887cc28ae6ddcffe82f11a27e0ba263d9f747658b45f8a97` |
| rustbgpd | Source contains the post-M103 boundary `350eb813b7a2a71ccfae2084d033253e96419cea`; the driver requires the exact checked-out SHA and records the same-run local `rustbgpd:dev` image ID |

The ARouteServer manifest is a single linux/amd64 image manifest, not an image
index. The workflow therefore checks its schema, exact config digest, local
image ID, architecture, and installed Python package version independently.
The upstream tag commit is provenance, not a substitute for those runtime
checks.

## Immutable inputs

The driver and the Rust topology contract pin these M90 inputs byte for byte:

| M90 input | SHA-256 |
|---|---|
| `general.yml` | `c47fed81ba4c7b3671d8c3f3a26955037e5cef67e7c7b7650dc9bf3ceaeb214d` |
| `clients.yml` | `08ceca5f9bafb13139538096a94595d075b7a7dae9342deb26d7f5adfc337e1e` |
| `context.yml` | `f979b7b72f9385bf5e10258b967c22da0ec1bd5b214ad9f42197fcd104471eda` |
| `context-sectioned.yml` | `f61c2a6d88aae1bb11c9ea95a4dd73abfb3c2f2577df69316f10d49e436b8790` |
| `announcements.json` | `e55a7faea278b962139a17fe5daf81026761b6eef57cb8bb7807005c12f8164a` |
| `bogons.yml` | `26e7c313a41fd7a854f73c656a77415fd9c2bb9057b625a7592bd436ee26dfe5` |
| `arouteserver.yml` | `c3b85f1af54c437ae50b0d4e1502b3a6e95cb2c4b12c255ac1c90cfc9eec5b19` |
| `bgpq4-stub.sh` | `cebb06da5c9adff5184652bca877ab7956f137c5d9cd425b7c449ad0e950bb84` |
| `policy-explain.toml` | `811634752dee124d80be1b0836c61f1a5f20af32b3c94c7fb48536573fd98030` |
| `prove-context-ingestion.sh` | `638d50ee11b4ff4b55ae888d69ecde0225d4d69a6b6f6b9d7a1250b54e2b2270` |
| `gobgp-m90-member1.toml` | `b7d897cb35aa657d469dbc7c35d9bdff2b346dc7169bcf820a331a06866f33e2` |
| `gobgp-m90-member2.toml` | `1cfea7eee37eb764a5ab8f090d7f3f25d252ed18d8ff0b9b7f9dbf5e2defd329` |
| `gobgp-m90-member3.toml` | `27e3955e743203ba352f177eb5e0899d061520bd14e7c0412a02007073c74f72` |

The corpus remains exactly four accepts and seven rejects. The two member2 IRR
rejects use the executable current term
`client-as64501-1 / reject-irrdb-prefix-filtered`; M104 does not copy the stale
historical `rest` prose from M90's summary.

## Acceptance boundary

The proof is green only when both halves pass in the same checkout:

1. The unchanged M90 context-ingestion proof finishes exactly 23/23. It runs a
   fresh pinned-image `template-context` dump, requires byte equality with the
   archived sectioned fixture, requires both context shapes to render the same
   12-file tree, and runs strict config plus four policy checks.
2. The M104 live differential finishes exactly 74 passed / 0 failed. It checks
   every runtime/image/config identity before daemon start, renders BIRD for
   target 2.16, requires BIRD 2.19.2 `bird -p`, renders the current rustbgpd
   tree, drives all 11 routes, checks both verdicts, exact rustbgpd
   policy/term attribution and BIRD cause communities for every rejection,
   and requires all six sessions to survive.

Any input hash, image identity, source SHA, renderer output, manifest
cardinality, verdict, term, cause, or session delta stops the proof. There is
no golden-update path and the hosted job is single-attempt.

## Local run

Stage the exact BIRD archive and build the three images with the hosted pins:

```bash
work=$(mktemp -d)
.github/scripts/install-bird3.sh \
  --version 2.19.2 \
  --sha256 aff89abba3b92b7637bd57e0168b8d7ae887747f160ada4973378ad72f5f3660 \
  --prepare-archive "$work/bird-2.19.2.tar.gz"
.github/scripts/install-bird3.sh \
  --version 2.19.2 \
  --sha256 aff89abba3b92b7637bd57e0168b8d7ae887747f160ada4973378ad72f5f3660 \
  --stage-archive "$work/bird-2.19.2.tar.gz" tests/interop/bird3-archive

docker build --target dev -t rustbgpd:dev .
docker build -t bird:v2.19.2-m104 \
  -f tests/interop/Dockerfile.bird-v2192 tests/interop
docker build --build-arg TARGETARCH=amd64 \
  --build-arg GOBGP_VERSION=4.8.0 \
  --build-arg GOBGP_SHA256=43b570ae5cc1afab7aebdd9d8f4536e27656465848270c8a6f5fda1ffe093a03 \
  -t gobgp:v4.8.0-m104 -f tests/interop/Dockerfile.gobgp-v47 tests/interop
docker pull \
  pierky/arouteserver@sha256:ba0e9c0b541c63acf0765a08fd2e09c2bba9dc64af1f5bbdce7819e8d1c34d66
```

Then run both proof halves:

```bash
M90_ARS_IMAGE='pierky/arouteserver@sha256:ba0e9c0b541c63acf0765a08fd2e09c2bba9dc64af1f5bbdce7819e8d1c34d66' \
  bash tests/interop/m90-differential/prove-context-ingestion.sh

containerlab deploy -t tests/interop/m104-arouteserver-current-rs-differential.clab.yml
M104_EXPECTED_GIT_SHA="$(git rev-parse HEAD)" \
  bash tests/interop/scripts/test-m104-arouteserver-current-rs-differential.sh
containerlab destroy -t tests/interop/m104-arouteserver-current-rs-differential.clab.yml --cleanup
```

The offline destructive contract can run without Docker or containerlab:

```bash
bash tests/interop/scripts/test-m104-arouteserver-current-rs-differential.sh \
  --self-test-offline-contract
```
