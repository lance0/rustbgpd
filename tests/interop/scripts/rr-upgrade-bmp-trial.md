# RR upgrade comparison trial

This local trial compares genuine outgoing BMP from released rustbgpd v0.75.0
and main commit `56cc5c4af5a607951915d175966de17241fca9a9`. It exercises
the existing offline comparator through real RR sessions. It does not qualify
an external incumbent or establish vendor interoperability. Source preparation
alone is not a passing receipt.

Both RRs use AS 65001, IPv4 unicast, no configured Add-Path, the same default
iBGP policies, and cluster ID `192.0.2.1`. Their router IDs differ. One GoBGP
4.10.0 originator sends `198.51.100.0/24` to both; one GoBGP observer receives
both views at the same address. The observer advertises no routes and has no
forwarding integration. The original NEXT_HOP must survive reflection.

The existing M81 raw sink records independent TCP connections on ports 11019
and 11020. Both slots use BMP version 3 here. The driver waits for each actual
Initiation before enabling BGP peers. It concatenates original message bytes
from one connection without modifying them, then invokes the existing
`rbgp diff snapshot from-bmp` with the observer filter. The CLI verifies OPEN
negotiation and EOR completeness. The additional checker requires O=1/L=1,
one observer generation, a nonempty route inventory, and exact numeric type
9/10 flags and value bytes. GoBGP's separate per-neighbor Adj-RIB-In captures
prove actual observer delivery, including NEXT_HOP and reflection attributes.
Observer delivery can precede BMP export. Each phase therefore retries capture
and strict conversion for up to 30 attempts, one second apart, before comparing
the complete nonempty snapshots; a partial JSONL write or missing BMP data
cannot make the phase pass.

The equal phase must exit 0 with one matched route. The driver then disables
only main's two peer sessions, terminates that daemon, changes its actual
configured cluster ID to `192.0.2.2`, and restarts it. Peers stay disabled until
the new BMP connection has started. The divergent phase must exit 1 with
exactly one attribute-changed route and only the expected CLUSTER_LIST byte
difference; ORIGINATOR_ID remains present and unchanged. The incumbent stays
running with the same settled route. Each phase assigns its own shared capture
generation to the two conversions; this label does not itself prove simultaneity.

## Verified upgrade trial

The 2026-10-11 run used harness commit
`603ec963368605aac98366027f0cc4313de37270`, the released v0.75.0 daemon,
and the pinned main runtime above. Both BMP version 3 captures used O=1/L=1
toward the same observer, with Peer Up and End-of-RIB present.

| Phase | Complete generation | Comparator result |
|-------|---------------------|-------------------|
| Equal cluster IDs | 1 | Exit 0; one matched route |
| Main cluster ID changed to `192.0.2.2` | 2 | Exit 1; one attribute-changed route |

The only differing route attribute was CLUSTER_LIST (type 10, flags 128):
`c0000201` became `c0000202`. ORIGINATOR_ID (type 9, flags 128) remained
`c0000214`. Independent GoBGP 4.10.0 Adj-RIB-In checks confirmed delivery
of `198.51.100.0/24`, the original NEXT_HOP, and both reflection attributes
in each phase. The driver and owned cleanup both exited 0. This proves the
one-prefix IPv4 upgrade trial; external-incumbent qualification remains
outstanding.

## Admission and prerequisites

Use one exclusive lab slot. Do not overlap with CLI doctor/workspace tests,
other labs, or timing-sensitive measurements. There are five small containers,
four BGP sessions, two BMP streams and one prefix. Budget approximately 2 GiB
for the running lab and 1 GiB for binary/raw receipts. A cold dev-image build
is a separate substantial build request; reuse an image only after the source
guard proves its build inputs match the pinned commit. No shared image alias
needs to change.

Required host tools: Docker, containerlab, grpcurl, jq, Python 3, Bash, Git,
tar and sha256sum. The host must run Linux amd64 with a glibc loader and
libraries compatible with the Debian 12 (Bookworm) dev image: the driver copies
its `rbgp` comparator onto the host and executes it there. A `--version` probe
fails early with the loader error before either RR daemon starts if the host
cannot run it. Reuse these peer/helper images:

- `gobgp:v4.10.0-m76`, with both executable hashes checked by the driver.
- `bmpsink:m81`, from the existing `Dockerfile.bmpsink`.
- An immutable dev-image ID for the pinned main source, exported as
  `RR_MAIN_IMAGE=sha256:...`, and an owned retained alias such as
  `RR_MAIN_IMAGE_ALIAS=rustbgpd:rr-upgrade-56cc5c4af`. Containerlab requires
  the alias because it normalizes bare image IDs as registry references. The
  driver independently checks the alias and both containers against the
  immutable ID. Both RRs use that runtime environment; the incumbent runs
  the separately verified release executable. Never retag `rustbgpd:dev`.

Obtain the original [v0.75.0 Linux amd64 release archive](https://github.com/lance0/rustbgpd/releases/download/v0.75.0/rustbgpd-linux-amd64.tar.gz).
Set `RELEASE_ARCHIVE` to its path. The driver verifies SHA-256
`9aa9fe9f84162085ee5eef13f5090981550f1f45a5f9c3b37347178cff990489`
before extracting only `rustbgpd`. Its release commit is
`54ed19b5af927f1c8e5064ecb1a497885c15d068`. No download is hidden in the driver.

## Checks and execution

Before starting containers, run the source checks and checker controls:

```bash
bash -n tests/interop/scripts/test-rr-upgrade-bmp-trial.sh
shellcheck -x -P tests/interop/scripts tests/interop/scripts/test-rr-upgrade-bmp-trial.sh
python3 tests/interop/scripts/check-rr-upgrade-bmp-trial.py --self-test
git diff --check
```

Parse the two TOML templates after replacing their IP/port placeholders and
parse the topology using the existing local YAML tooling. These source checks
do not constitute RR qualification. Under exclusive runtime admission, deploy
and run from the repository root:

```bash
export RR_MAIN_IMAGE RR_MAIN_IMAGE_ALIAS RELEASE_ARCHIVE
export ARTIFACT_DIR=/tmp/rr-upgrade-bmp-receipt
containerlab deploy -t tests/interop/rr-upgrade-bmp-trial.clab.yml
CLEANUP=1 bash tests/interop/scripts/test-rr-upgrade-bmp-trial.sh
```

Retain the complete command log and its native exit separately. The driver
retains image identities, source IDs, executable hashes, effective configs,
daemon logs, each phase's raw sink JSONL, reconstructed original BMP stream,
converted snapshot, observer Adj-RIB-In/session JSON, comparator output and
exit status. `driver.exit` records the actual test outcome; `cleanup.exit`
records owned topology destruction separately. Cleanup failure makes the
overall command fail even when comparison passed. `CLEANUP=0` deliberately
leaves this topology available for diagnosis and requires explicit later
destruction with the same topology file. Never prune global Docker resources.

After a successful run, inspect the retained evidence and record an upgrade
trial receipt with its precise versions and scope. Keep external-incumbent
qualification outstanding. No CLI implementation, schema, dependency,
synthetic producer or passive packet-capture importer is added by this trial.
