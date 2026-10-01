# M113 Type 6 SMET reflection

M113 exercises Type 6 SMET receive, reflection, withdrawal, and error recovery
through one rustbgpd route reflector using controlled raw BGP peers on loopback.
A separate TShark decoder checks the complete reflected route identity and flags
against the captured TCP streams.

**Recorded result:** the [2026-10-01 receipt](../../../docs/artifacts/interop/m113-smet-20261001T180815Z/README.md)
passed 41 protocol phases across 15 TCP connections, with 46 reflected SMET
NLRIs checked by the independent TShark decoder. This is the bounded controlled
raw-peer proof described below; it does not establish vendor interoperability.

## Scope

The runner starts one explicitly supplied daemon and three normal raw peers:
a source, a lower-preference alternate, and a receiver, using `127.0.0.1`
through `127.0.0.4`. Six additional malformed-test source identities use
`127.0.0.5` through `127.0.0.10`. Each structural-error case resets and reconnects
its own peer once, preserving the 45-second acknowledgement deadline without
accumulating repeated-NOTIFICATION backoff on one peer. BGP router IDs, next
hops, and SMET originator fields have separate identities. No interfaces,
routes, namespaces, or host network settings are created. The Docker capture option uses host networking to observe the owned
loopback TCP port.

This is a bounded raw-peer wire proof. It does not establish vendor
interoperability, scale, performance, SMET origination, IGMP/MLD proxy behavior,
or multicast forwarding. EVPN remains alpha; see the
[Type 6 support boundary](../../../docs/reference/rfc-notes.md#type-6-smet-reflection).

## Requirements and live invocation

Run this separately from CLI doctor tests, which discover local daemon processes.
Use a Linux host with Python 3.11 or newer (the offline tests use `tomllib`),
a freshly built rustbgpd binary for the revision under test, an unused TCP port,
and a new output directory. The runner creates it with mode `0700` and places runtime
state beneath it. Keep the output path short enough for the Unix API socket
(the runner checks the platform's 108-byte pathname limit).

The live decoder is pinned to **TShark 4.2.2** and this binary SHA-256:

```text
1be3296c467ba299c4e89b4d6a2dfb8d0985a8bba2a8af3fa2ac3f10c3062668
```

A matching version string alone is insufficient. The runner refuses a different
binary. Its Type 6 field layout was checked against upstream `packet-bgp.c` at
commit `40459284278611128aac5cef35a563218933f8da`.

For Docker capture, set `M113_CAPTURE_IMAGE` to an existing image containing
`tcpdump` with `--immediate-mode` support. The runner enables immediate
capture and packet-buffered PCAP writes (`-U`) so final packets are retained
before capture shutdown. An image ID or digest identifies the image without
relying on a mutable tag. Docker must be available to the invoking user. The image supplies capture
only; the pinned TShark binary runs on the host.

Run from the repository root, with `/tmp/m113-smet` absent:

```bash
python3 tests/interop/scripts/m113_smet_oracle.py \
  --daemon target/release/rustbgpd \
  --output /tmp/m113-smet \
  --capture-image "$M113_CAPTURE_IMAGE"
```

| Option | Meaning |
|---|---|
| `--daemon PATH` | Explicit daemon binary; its SHA-256 is recorded. Required for a live run. |
| `--output DIRECTORY` | New artifact directory; existing paths are refused. Required for a live run. |
| `--capture-image IMAGE` | Owned Docker container running `tcpdump` on the selected loopback port. |
| `--capture-sudo` | Alternative capture using existing `sudo -n tcpdump` permission; mutually exclusive with `--capture-image`. |
| `--tshark PATH` | Host decoder path, default `tshark`; must match the frozen binary. |
| `--port PORT` | Loopback BGP port, default `21179`; the runner refuses an existing listener. |
| `--timeout SECONDS` | Per-phase wire acknowledgement deadline, default `45`. |

Without either capture option, host `tcpdump` must already have capture
permission. The runner stops its own daemon and capture process/container on
completion or failure. SIGTERM unwinds through cleanup; forced termination and
cleanup errors prevent a successful receipt. It does not prune other Docker
resources.

## Phases and acceptance

1. Reflect four literal wire shapes: IPv4 `(*,G)`, IPv6 `(S,G)` with an IPv4
   originator, and familyless `(*,*)` with IPv4 and IPv6 originators. Preserve
   the raw flags, Route Target, next hop, ORIGINATOR_ID, and CLUSTER_LIST.
2. Keep different SMET originators as distinct keys, then replace flags on one
   key without a withdrawal or duplicate announcement.
3. Admit a lower-preference alternate without disturbing the winner. A
   zero-flags withdrawal selects the alternate; withdrawing its last path
   removes the key.
4. Send a canonical invalid announcement flag profile with a valid announced
   sibling and an explicit withdrawal. Require all affected keys to withdraw,
   preserve unrelated routes, and recover on the same BGP session.
5. Test missing flags, an extra byte, and mixed source/group families in both
   MP_REACH and MP_UNREACH. Require UPDATE error `3/9`, no receiver route
   transition during the reset wait, an alternate-source marker/withdrawal
   barrier, same-peer reconnection, and successful announce/withdraw recovery.
   The six cases use separate source identities to isolate protocol handling
   from repeated-NOTIFICATION backoff.

A phase completes only after the exact expected multiset of receiver event
kinds and keys arrives and the receiver state matches. Wrong payloads,
unrelated changes, same-key withdrawal/reannouncement churn, and duplicate
transitions fail. The reset marker supplies receiver-stream evidence after the
source notification; elapsed time alone is not an absence assertion.

The PCAP checker reassembles each connection, rejects TCP gaps and conflicting
overlaps, compares sent and received BGP transcripts, and rejects unread trailing
receiver UPDATEs or notifications. Every captured receiver event must equal the
ordered concatenation of accepted phase events. Independent TShark PDML must
match the full RD, Ethernet Tag, source/group/originator address lengths and
values, and flags, including explicit wildcard absence and reserved flag bits.

## Artifacts and offline controls

Keep the output directory intact. A completed run contains `rr.toml`, `daemon.log`,
`capture.log`, `m113.pcap`, `payloads.tsv`, `reflected.pdml`, and `result.json`.
The result records binary identities, connections, phase evidence, capture
hash, and process exits. Individual `PASS` lines are progress; the complete
result and successful cleanup determine the outcome.

Run the checker controls without a daemon or capture privileges:

```bash
python3 -m unittest discover -s tests/interop/scripts -p test_m113_smet_oracle.py
```

Controls cover malformed layouts, wrong reflected attributes, distinct
identities, omitted withdrawals, same-key churn and duplicates, transient reset
churn that returns to an empty state, incomplete event receipts, incorrect or
missing decoder fields, and cleanup failures. The literal PCAP decoder test
requires the pinned TShark binary and otherwise skips; a skip is not decoder
validation.

Replay an existing successful artifact directory without launching the daemon,
Docker, or TShark:

```bash
python3 tests/interop/scripts/m113_smet_oracle.py --replay /tmp/m113-smet
```

Replay requires the retained result, PCAP, payload rows, and PDML. It checks the
recorded clean exits and decoder identity, PCAP/payload/PDML hashes, transcripts, accepted
phase events, and complete decoded keys. It verifies retained evidence; it does
not rerun the protocol exchange or independently regenerate the saved TShark
output.
