# M92 — GoBGP v4.7 route-server differential

This local receipt compares a GoBGP 4.7.0 incumbent route server with a
rustbgpd candidate over one dual-stack IXP LAN. Two GoBGP sources inject five
routes into both servers; an independent BIRD 2 target receives four baseline
routes (2 IPv4 + 2 IPv6). The fifth, `2001:db8:92ff::/48`, is denied only by
the target export policies. The separate allowed source2 IPv6 route proves the
family remains healthy while that exact prefix is filtered.

## Run

```bash
docker build --target dev -t rustbgpd:dev .
docker build -t bird:2-bookworm -f tests/interop/Dockerfile.bird tests/interop
docker build -t gobgp:v4.7.0-m92 -f tests/interop/Dockerfile.gobgp-v47 tests/interop
containerlab deploy -t tests/interop/m92-gobgp-v47-rs-differential.clab.yml
bash tests/interop/scripts/test-m92-gobgp-v47-rs-differential.sh
M92_COMPLETENESS_NEGATIVE=1 \
  bash tests/interop/scripts/test-m92-gobgp-v47-rs-differential.sh
containerlab destroy -t tests/interop/m92-gobgp-v47-rs-differential.clab.yml
```

The normal driver starts fresh daemon processes for baseline, mutant, and
restore rounds. Before BIRD starts, both RSs must hold the exact five-route
source inventory. BIRD then must hold exact protocol-scoped counts and
sentinels. PDML parsing enumerates every BGP PDU within a frame and requires
one IPv4 and one IPv6 EoR after the last family NLRI tuple. Only then does the
driver convert GoBGP adj-out and run one `rbgp diff advertised`, with canonical
incumbent captures required equal before and after it.

Expected normal verdicts are: baseline `in_sync`/exit 0; a one-line rustbgpd
deny-to-permit mutation with exactly one `rustbgpd_only` row/exit 1; and a
byte-identical fresh restore with `in_sync`/exit 0. The opt-in negative disables
GR only on the GoBGP target neighbor: BIRD still holds all four routes, but
both GoBGP EoR counts must be zero and the run stops before snapshot/diff.
GoBGP adj-out EOF is never treated as convergence.

## Archived local receipt

The final run on 2026-07-19T20:18:52Z–20:19:51Z used parent
`4e2ea38b88c7478aa144473f95095776b5463a82` and these local image IDs:

- rustbgpd: `sha256:e2fb168ecd31ff9656a428268cd9bf5ba5c7e2952e68b5f37b7d577476b1d8b2`
- GoBGP 4.7.0: `sha256:5af7e3e7e83b763cbcc142478acee1d4fe368315f182b0e8820938d008297150`
- BIRD 2.0.12: `sha256:0a10365bbd587a4bf12c9324bdcf414cef611eed7cafbefe907d5d704bb1b7ca`

The normal receipt passed 56/56 checks: baseline and restore were `in_sync`
with four matches, while the mutant exited 1 with exactly one IPv6
`rustbgpd_only` row. The separate completeness negative passed 17/17 checks:
both four-route BIRD views were exact, GoBGP IPv4/IPv6 EoR counts were both
zero, rustbgpd EoRs remained complete, and no snapshot or diff ran.

Sanitized input SHA-256 values:

| Input | SHA-256 |
|---|---|
| `Dockerfile.gobgp-v47` | `ec53867a7b517a4587bbe11c7c4698cffd6a0d62e86e54e7c7d6d7552c6a3ed3` |
| topology | `6c0a559827ceaa291acca8d25f2b2257d8da1603d19a7c2798ce40a47a0dbd21` |
| rustbgpd config | `957f6630f1f52d1e4030523661ba653b41253ba2a2a961c09b508fcdf99c373a` |
| GoBGP RS config | `cf4061b00f13c4b5bdb369af5fa2b8648b48b1296bae456349fe8dacc027b925` |
| GoBGP source1 config | `b73b64105cad2d222825285bfad93813a33ff72dac09dabafb2bc6b24ac5d4c3` |
| GoBGP source2 config | `27b9e7036645e00fc1b779bb05a1402e5adf70578f88c405287dac44e885d7e1` |
| BIRD target config | `61fbbba70926ec33589aef64ec1a9adc374ec953bdd732a6bce41df059c77d1b` |
| driver | `7d5ed3bf0371f59ccb4440536a8db5c6299e4c606372e6d330c94dc7ab7dfd5f` |
| raw GoBGP capture | `ab8d50f0f7e468837e93d85a6ff69640f2937535db71c28fe5c624ed0d794c84` |
| expected ribsnap | `664ee668f34acfd4a3ba23066a7e22ce2d8c092ccf1852cb9252fb1a729f1dd6` |

## Pins and load-bearing breaks

The image downloads the official amd64 v4.7.0 release archive, checks SHA-256
`05d98ca0d7bbcb2f50a6b7b6ee51c5e5b5fd64d6a310ee807040ed9d7104d5e0`,
and asserts both binary versions. The raw capture and golden exercise both
families plus MED, standard community, and large community.

- Removing either export deny makes baseline divergent.
- Removing MP_REACH conversion makes the v4.7 golden test red.
- Removing or reordering an EoR fails completeness before diff; disabling
  target GR proves the missing-both case with routes still present.
- Removing the one-line mutant makes the required divergent row absent.
- Failing to restore the config byte-for-byte makes the final hash gate red.
- Deleting the golden inventory entry makes the v1 stable-surface gate red.

Recorded red proofs restored before the final run: each export deny removed;
the one-line mutant made a no-op; tuple ordering reduced to frame-only;
MP_REACH mapping removed; the IPv6 mock inventory dropped; the stable-surface
golden pin deleted; the EoR check bypassed; and the restore hash forced unequal.
Each failed at its named inventory, golden, summary, completeness, or hash gate.

This is synthetic interoperability evidence only. It does not close or stand
in for the demand-gated external shadow/canary pilot.
