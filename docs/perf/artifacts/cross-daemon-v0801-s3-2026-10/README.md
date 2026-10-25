# Flap-storm (S3) v0.80.1 addendum artifacts (2026-10-25)

These files are the evidence for the
[v0.80.1 flap-storm addendum](../../cross-daemon-v0801-s3-2026-10.md): three S3 legs of the
v0.80.1 tag (`2fb2cbf27`, clean) at 700 members × 400,400 prefixes with 50 flapping, on the host
and inputs of the [v0.80.0 bundle](../cross-daemon-v0800-2026-10/README.md).

- **`comparison.json`** is the curated comparison: source identity, shape, each leg's verdict
  and per-round p50/p95/maximum, memory, the nine-round bands, and the comparator bands the
  receipt cites.
- **`matrix/matrix-rustbgpd-r{1,2,3}-s3/`** holds each leg's `reloadstall.log`, `status`,
  5-second `rss.csv`, `vmhwm`, swap-fenced `cgroup-memory`, runner `provenance.json` and gzipped
  daemon log. These follow the v0.80.0 bundle, which also commits its raw leg files; this
  addendum has no CI run to hold them.
- **`summary.csv`, `report.md`, `establishment-span.csv`** are
  [`summarize.py`](../../../../bench/scale/headline/summarize.py) output; `summarize.py <bundle>`
  reproduces every row of `summary.csv` (in a different row order); `establishment-span.csv`
  needs the daemon logs uncompressed.
- **`identity.txt`** records commit, tree, binary SHA-256s, build commands, CPUs and kernel.

Leg files and summarizer output are copied unedited; `comparison.json` and `identity.txt` are
written from them and the build records. The daemon logs are gzipped with no stored name or timestamp. Every
file, including the decompressed logs, was searched for host names, home directories and user
names; none occur, and the only paths are the harness's `/tmp/ixp-rustbgpd/` directory, as in
the v0.80.0 bundle. Run logs and host-quiet samples carry local paths and are not included;
the receipt quotes their load readings. Scenario configurations and metrics scrapes are not
included.

| File | SHA-256 |
| --- | --- |
| `comparison.json` | `63ddc6b702ee92fb3a80384648d2e4a8e0c223562b0d96428543de3aea404674` |
| `establishment-span.csv` | `a1c519ba2684074d284fbd53034023c8d436df04111cc90d11817d5b1201712d` |
| `identity.txt` | `c164eb5721428d7ea0de163040a878218e09dbbdaf9b218108dc01880bcd56fe` |
| `matrix/matrix-rustbgpd-r1-s3/cgroup-memory` | `a2e1de1b87a9934bec198901f35bf2a832aa6946320cc12d37acbc6a1f2160f2` |
| `matrix/matrix-rustbgpd-r1-s3/daemon.log.gz` | `fd2955ec114b0b69ae522565b11437932c17448de443880cb6c4eccad4408cbf` |
| `matrix/matrix-rustbgpd-r1-s3/provenance.json` | `eb592be4ec16e977b5547d096cd11c11a9ab3a20f319d1c9d6242d7f783240cf` |
| `matrix/matrix-rustbgpd-r1-s3/reloadstall.log` | `77b78da66f1e9fbf2d7b2683c0bf1df9e380c51d5623ceb93c606bd7a3e11533` |
| `matrix/matrix-rustbgpd-r1-s3/rss.csv` | `cf204b5b40a3b97ae628da481f101fbb7a61e4bd97d94d24412d4dc456809e4d` |
| `matrix/matrix-rustbgpd-r1-s3/status` | `9f56e761d79bfdb34304a012586cb04d16b435ef6130091a97702e559260a2f2` |
| `matrix/matrix-rustbgpd-r1-s3/vmhwm` | `5d755c78186a25a17706e47a63e1bd21ed416fa4c2ee8496a827d5e05af434e8` |
| `matrix/matrix-rustbgpd-r2-s3/cgroup-memory` | `7ec57f4b414335b1fc1a0d30a4713c218416f505c7cc451ad15e3f6e47f70007` |
| `matrix/matrix-rustbgpd-r2-s3/daemon.log.gz` | `b51eff17f1516d1e12cc86e25555c56cc6e24ea682da5f0a3eaeae2e39718929` |
| `matrix/matrix-rustbgpd-r2-s3/provenance.json` | `eb592be4ec16e977b5547d096cd11c11a9ab3a20f319d1c9d6242d7f783240cf` |
| `matrix/matrix-rustbgpd-r2-s3/reloadstall.log` | `6f5e6bed981537b1dd6aaaad601c8a4ee6fd26ba38c64cf675f9633be85091a7` |
| `matrix/matrix-rustbgpd-r2-s3/rss.csv` | `9300a9d6afceff036734e14d6e5ab028ecd6aa1e2e88ee0943b88f0dbf1bc398` |
| `matrix/matrix-rustbgpd-r2-s3/status` | `9f56e761d79bfdb34304a012586cb04d16b435ef6130091a97702e559260a2f2` |
| `matrix/matrix-rustbgpd-r2-s3/vmhwm` | `c16c188afb443617d5218449f9fec7eb32531af7e797615a4e24a8ac3cce2989` |
| `matrix/matrix-rustbgpd-r3-s3/cgroup-memory` | `9252d81515fdfc694bdb11a01cc7e214b195296a61ac95cd0d709be3f28dcb60` |
| `matrix/matrix-rustbgpd-r3-s3/daemon.log.gz` | `93c424aed55cf55179ac8f96115edea2c81071ca60cd58d4e831ba69a0f02320` |
| `matrix/matrix-rustbgpd-r3-s3/provenance.json` | `eb592be4ec16e977b5547d096cd11c11a9ab3a20f319d1c9d6242d7f783240cf` |
| `matrix/matrix-rustbgpd-r3-s3/reloadstall.log` | `8ac6bbf969274deb925dde7c4bdb607272589f316a36f48c2ac4bc4f98201ad4` |
| `matrix/matrix-rustbgpd-r3-s3/rss.csv` | `5804aed6c6329a669ea66f8322764510175a79d19d7e2035c88b75629cdceaba` |
| `matrix/matrix-rustbgpd-r3-s3/status` | `9f56e761d79bfdb34304a012586cb04d16b435ef6130091a97702e559260a2f2` |
| `matrix/matrix-rustbgpd-r3-s3/vmhwm` | `4d741c901a73c1d01213d2c11484935510e29daea529cbac6dc2a91eb93217e5` |
| `report.md` | `6432e188680139de7260f20496ca03915e6411e101257bd2da59168a10d1f856` |
| `summary.csv` | `ccfcf9f91c3cf01be7eaaca218f8c5d9ec5c0eb139504da96caeb96c5993ec69` |

`sha256sum -c SHA256SUMS` checks the same files plus this README.
