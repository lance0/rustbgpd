# M22 FlowSpec controller qualification — 2026-10-02

The bounded controller lifecycle passed against **FRR 10.7.1** with 100 local
rules: 50 IPv4 FlowSpec and 50 IPv6 FlowSpec, carried over one eBGP session.
The final driver exited 0 and removed its containers. This is functional
control-plane evidence for the current alpha API, not a stability promotion,
throughput measurement, soak, or forwarding test.

The daemon was built from `326dc11218f70f75d1a9a103118682d3ab0b1a5a` with
`cargo build --locked --release --bin rustbgpd -j 8` and its default jemalloc
feature. The locally compiled binary ran in a Debian 13 lab runtime; CI uses
the repository's `dev` image. [Identity](identity.json) records the compiler,
binary/image hashes, FRR image, and qualification driver/configuration hashes.

## Workload and checks

Each rule matches one destination prefix, TCP, and destination port 80. The
driver checks complete component identities, AFI, actions, communities, raw
extended communities, and source identity in the local, selected, and committed
advertised API views. It checks matching NLRI, selected paths, traffic rates,
and rewritten route targets in FRR's table and detailed JSON output.

- Create all 100 rules, reapply with `UNCHANGED`, and replace traffic rates
  from 1000 to 2000 bytes/second with `REPLACED`.
- Deny one rule per AFI on export while retaining both locally. Add standard
  community `65001:100` and route target `65001:100` to the other 49 rules per
  AFI; local payloads remain unchanged. FRR's detailed view exposes the route
  target, while the API also verifies the standard community.
- Prefer a received candidate for one key per AFI. Retain the outselected local
  intent, replace it with rate 4000, delete only that local intent, and recreate
  it. The received winner keeps rate 3000 until the source withdraws it.
- Disconnect and reconnect the destination peer; verify exact replay without
  reinjection. Restart the daemon; prove all local intent is absent, then
  reconcile all 100 rules explicitly and verify their distribution again.
- Delete all rules, verify `NOT_FOUND` for a repeated default delete and
  `NOT_PRESENT` with `allow_missing`, and observe empty tables at the end.

Both view-mode acknowledgements are required, including empty responses.
Individual RPCs have a 10-second deadline; convergence polls use 30 seconds
and session establishment uses 90 seconds. Session counters remain unchanged
between deliberate lifecycle operations. The reconnect and daemon restart
each cause exactly one FRR session drop. The
[result](result.json) lists the 19 completed checks; the
[driver log](driver.log) retains their output with ANSI formatting removed and
local filesystem paths replaced. [Observations](observations.tar.gz) contain
the complete RPC responses, FRR table JSON, parsed detailed rows, and session
counter comparisons at each phase. [Checksums](SHA256SUMS) cover these files.

Five offline oracle tests reject wrong identities, actions, communities,
sources, duplicate rows, invalid FRR paths, and malformed detailed output.
Earlier driver-development attempts exposed fixture and display-format
assumptions; they did not change production code. This receipt records the
final complete run, not those incomplete attempts.

## Reproduce

From the repository root, build the ordinary lab image and deploy a fresh M22
topology. Run this driver separately from M22's receive-validation driver:

```bash
docker build --target dev -t rustbgpd:dev .
containerlab deploy -t tests/interop/m22-flowspec-frr.clab.yml
python3 tests/interop/scripts/test_m22_flowspec_controller.py
CLEANUP=1 bash tests/interop/scripts/test-m22-flowspec-controller.sh
```

An optional first argument selects a new observation directory. The existing
M22 CI job runs the controller driver on a fresh deployment after the original
M22 test, using the existing retry and cleanup action.

## Limits

Receive-side feasibility validation stays off. GR is disabled at the tested
daemon's neighbors; this receipt does not qualify GR/LLGR retention or selection
deferral. Injection remains process-local, and the committed advertised view
means admission to the local outbound channel. FRR observation here does not
turn that API acknowledgement into a remote acceptance or enforcement promise.

The three controller RPCs, `Config.flowspec`, and receive-side validation
remain outside the v1 inventory. The scoped promotion decision still requires
its inventory, contract, compatibility exclusions, and upgrade review.
[ADR-0125's dated unicast receipts](../../../adr/0125-v1-stability-contract.md)
remain unicast evidence and are not reused as FlowSpec qualification.
